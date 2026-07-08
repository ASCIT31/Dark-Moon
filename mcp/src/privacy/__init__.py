"""
Darkmoon privacy gateway — reversible local tokenization.

The LLM must never see real sensitive values (IPs, hostnames, domains, URLs,
emails, usernames, credentials, internal paths). It only ever sees deterministic
placeholders (IP_PRIVATE_001, HOST_INTERNAL_001, ...). Real values are injected
locally, right before tool execution, and are re-tokenized out of any output
before it goes back to the LLM.

- PrivacyVault  : creates/stores the placeholder<->value mapping (per session),
                  protects it locally, enforces TTL, never logs raw values.
- CommandGateway: context-aware rehydration of LLM-generated commands / tool
                  calls, blocks exfiltration, sanitizes output.
"""

from .vault import PrivacyVault, Category, PLACEHOLDER_RE
from .gateway import CommandGateway, GatewayResult, GatewayDecision

__all__ = [
    "PrivacyVault",
    "Category",
    "PLACEHOLDER_RE",
    "CommandGateway",
    "GatewayResult",
    "GatewayDecision",
]
