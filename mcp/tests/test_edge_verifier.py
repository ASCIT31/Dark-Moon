


def _necessity_lines(compacted):
    h = "hfp"
    lines = [
        {"cx": "c1", "ex": "ex_a", "seq": 1, "t": 1, "p": [["v1", "token"]], "c": [], "i": [],
         "e": [[h, "POST", "p_login", 200, 0, "ok"]]},
        {"cx": "c2", "ex": "ex_n", "seq": 2, "t": 2, "p": [], "c": [], "i": [],
         "e": [[h, "GET", "p_users", 401, 0, "refused"]]},
        {"cx": "c3", "ex": "ex_b", "seq": 3, "t": 3, "p": [], "c": [["v1", "c1", "token"]], "i": ["v1"],
         "e": [[h, "GET", "p_users", 200, 1, "ok"]]},
    ]
    if compacted:
        lines.insert(0, {"cx": "cx_000000000000", "seq": 0, "t": 0, "i": [], "x": False, "compacted": 12})
    return lines


def test_compacted_run_never_demonstrates_necessity():
    """Compaction may drop a success WITHOUT the value: necessity can no longer be ruled in (observed flow at most).
    Control: the same run, not compacted, demonstrates necessity."""
    from api.edge_verifier import executions_from_lines, verify_edge
    A = {"id": "fA", "run_id": "R1", "push_seq": 10, "evidence_execution_ids": ["ex_a"], "enabled_by": []}
    B = {"id": "fB", "run_id": "R1", "push_seq": 10, "evidence_execution_ids": ["ex_b"], "enabled_by": ["fA"]}
    states = {}
    for compacted in (False, True):
        execs = executions_from_lines(_necessity_lines(compacted), "R1")
        states[compacted] = verify_edge(A, B, {"executions": execs, "findings": [A, B]})[0]
    assert states == {False: "causal_necessity_demonstrated", True: "observed_flow"}


# ================================================================================================================
# Added after mutation testing (17/11/2026, reports/40-paths-v2/MUTATION-RESULTS.md, catalogue T1-T37).
# Each test is written from CONTRACT.md (+ its 17/11 clarifications); the verify_edge scenarios that the
# independent harness can express are sealed there (MT-01..MT-26); what it cannot express is here:
# - engine-level shapes the harness never feeds (findings= argument, list-form records, malformed input, refs detail);
# - ledger reading: run-ledger lines -> contract execution records (executions_from_lines and its helpers).
# ================================================================================================================
import time as _time

import pytest

from api import edge_verifier as ev

RUN = "R1"
V, W = "fp-v-" + "a" * 20, "fp-w-" + "b" * 20


def X(eid, seq, produced=(), consumed=(), presented=(), outcome="success", basis="http_2xx", keys=("op:b",), run=RUN,
      ckeys=None, **kw):
    d = {"execution_id": eid, "run_id": run, "seq": seq, "t": seq, "session": None,
         "produced": [{"fp": f, "kind": "token"} for f in produced],
         "consumed": [dict({"fp": f, "producer_execution_id": p}, **({"operation_keys": ckeys[i]} if ckeys else {}))
                      for i, (f, p) in enumerate(consumed)],
         "presented": list(presented), "outcome": outcome, "outcome_basis": basis, "operation_keys": list(keys)}
    d.update(kw)
    return d


def FD(fid, ids, enabled_by=(), push_seq=100, run=RUN, **kw):
    d = {"id": fid, "push_seq": push_seq, "evidence_execution_ids": list(ids), "enabled_by": list(enabled_by)}
    if run is not None:
        d["run_id"] = run
    d.update(kw)
    return d


FA, FB = FD("A", ["ex_a"]), FD("B", ["ex_b"], ["A"])
BASE = [X("ex_a", 1, produced=[V], keys=["op:a"]), X("ex_b", 3, consumed=[(V, "ex_a")])]


def sr(a, b, ledger, **kw):
    s, r, _ = ev.verify_edge(a, b, ledger, **kw)
    return s, r


# ------------------------------------------------------------------------------------- verify_edge: engine-level shapes
def test_t1_explicit_findings_argument_drives_the_cycle_check():
    """A declares C, C declares B, B declares A: A transitively depends on B -> cycle, from the findings= argument
    (the ledger carries no findings); without the argument nor ledger findings there is nothing to walk."""
    a = FD("A", ["ex_a"], ["C"])
    findings = [a, FD("C", [], ["B"]), FB]
    assert sr(a, FB, {"executions": BASE}, findings=findings) == ("declared_unverified", "cycle")
    assert sr(a, FB, {"executions": BASE, "findings": findings}) == ("declared_unverified", "cycle")
    assert sr(a, FB, {"executions": BASE})[0] == "observed_flow"
    # an explicit (even empty) findings list wins over the ledger's
    assert sr(a, FB, {"executions": BASE, "findings": findings}, findings=[])[0] == "observed_flow"


def test_t11_list_form_records_read_like_dicts_and_malformed_entries_never_raise():
    want = sr(FA, FB, BASE)
    assert want == ("observed_flow", None)
    pa = [dict(BASE[0], produced=[[V, "token"]]), BASE[1]]
    pb = [dict(BASE[0], produced=[[V]]), BASE[1]]
    pc = [dict(BASE[0], produced=[(V, "token")]), dict(BASE[1], consumed=[[V, "ex_a"]])]
    pd = [BASE[0], dict(BASE[1], consumed=[(V, "ex_a", "extra")])]
    for led in (pa, pb, pc, pd):
        assert sr(FA, FB, led) == want, led
    # malformed entries are no evidence, and never an exception
    junk = [dict(BASE[0], produced=["zq", {"kind": "token"}, [], None, 7]),
            dict(BASE[1], consumed=[{"producer_execution_id": "ex_a"}, ["z"], "zq", None, (V, "ex_a")])]
    assert sr(FA, FB, junk) == ("declared_unverified", "value_not_consumed")
    # a non-list truthy entry is never read as a value (no 1-char phantom fingerprint)
    phantom = [dict(BASE[0], produced=["zq"]), dict(BASE[1], consumed=[("z", "ex_a")])]
    assert sr(FA, FB, phantom) == ("declared_unverified", "value_not_consumed")
    # a consumption naming no producer links to nothing, whatever the executions are called
    for pid in (None, ""):
        magic = [dict(BASE[0], execution_id="XXXX"), X("ex_b", 3, consumed=[(V, pid)])]
        assert sr(FD("A", ["XXXX"]), FB, magic) == ("declared_unverified", "value_not_consumed")
    # a dict entry without fp but with other keys is skipped, the valid entry still counts
    tolerant = [dict(BASE[0], produced=[{"kind": "x", "other": 1}, {"fp": V, "kind": "token"}]),
                dict(BASE[1], consumed=[{"producer_execution_id": "ex_a", "x": 1}, {"fp": V, "producer_execution_id": "ex_a"}])]
    assert sr(FA, FB, tolerant) == want


def test_t11_singular_operation_key_and_bad_seq():
    ctl = X("ex_c", 2, outcome="refused", basis="http_refused", keys=[], operation_key="op:b")
    assert sr(FA, FB, BASE + [ctl])[0] == "causal_necessity_demonstrated"
    eb = dict(BASE[1], operation_keys=[], operation_key="op:b")
    assert sr(FA, FB, [BASE[0], eb, X("ex_c", 2, outcome="refused", basis="http_refused")])[0] == \
        "causal_necessity_demonstrated"
    for bad in (None, "x", "", [1]):
        assert sr(FA, FB, [BASE[0], dict(BASE[1], seq=bad)]) == ("declared_unverified", "unknown_execution")
    assert sr(FA, FB, [BASE[0], dict(BASE[1], seq="3")])[0] == "observed_flow"


def test_t12_blank_evidence_ids_are_no_ids():
    for ids in ([" "], ["", "  "], "ex_b", None):
        assert sr(FA, FD("B", [], ["A"], evidence_execution_ids=ids), BASE) == ("declared_unverified", "no_execution_ids")
    assert sr(FD("A", [" "]), FB, BASE) == ("declared_unverified", "no_execution_ids")
    # a blank declared enabler is no declaration
    assert sr(FA, FD("B", ["ex_b"], [" ", "Z"]), BASE) == ("declared_unverified", "not_declared")
    assert sr(FA, FD("B", ["ex_b"], [" A "]), BASE) == ("declared_unverified", "not_declared")


def test_t13_messy_findings_list_still_verifies_in_bounded_time():
    findings = ["junk", None, {"title": "no id"}, {"id": "C", "enabled_by": ["D"]}, {"id": "D", "enabled_by": ["C"]},
                {"id": "E", "enabled_by": ["ghost"]}, {"id": "A", "enabled_by": ["E"]}, FB]
    t0 = _time.perf_counter()
    assert sr(FD("A", ["ex_a"], ["E"]), FB, {"executions": BASE, "findings": findings}) == ("observed_flow", None)
    assert _time.perf_counter() - t0 < 1.0
    # A -> C, C <-> D (a cycle not through B), D -> B : A reaches B -> cycle, found through the C/D loop
    findings2 = [FD("A", ["ex_a"], ["C"]), {"id": "C", "enabled_by": ["D"]}, {"id": "D", "enabled_by": ["C", "B"]}, FB]
    assert sr(findings2[0], FB, {"executions": BASE, "findings": findings2}) == ("declared_unverified", "cycle")
    # a declared loop C <-> D reachable from A but not reaching B: terminates, no cycle for A -> B
    loop = [FD("A", ["ex_a"], ["C"]), {"id": "C", "enabled_by": ["D"]}, {"id": "D", "enabled_by": ["C"]}, FB]
    t0 = _time.perf_counter()
    assert sr(loop[0], FB, {"executions": BASE, "findings": loop}) == ("observed_flow", None)
    assert _time.perf_counter() - t0 < 1.0
    # a long acyclic declaration chain far from A/B is walked without error
    long = [{"id": f"N{i}", "enabled_by": [f"N{i + 1}"]} for i in range(300)]
    assert sr(FD("A", ["ex_a"], ["N0"]), FB, {"executions": BASE, "findings": long + [FB]})[0] == "observed_flow"


def test_t15_id_less_findings():
    no_id = FD("A", ["ex_a"])
    no_id.pop("id")
    for declared in (["XXXX"], ["None"], [""]):
        assert sr(no_id, FD("B", ["ex_b"], declared), BASE) == ("declared_unverified", "not_declared")
    assert sr(dict(FA, id=None), FD("B", ["ex_b"], ["None"]), BASE) == ("declared_unverified", "not_declared")
    b = FD("B", ["ex_b"], ["A"])
    b.pop("id")
    # B without id: no spurious duplicate / cycle (A declares the literal 'XXXX' and '')
    assert sr(FD("A", ["ex_a"], ["XXXX", ""]), b, BASE) == ("observed_flow", None)
    assert sr(None, FB, BASE) == ("declared_unverified", "not_declared")
    assert sr(FA, None, BASE) == ("declared_unverified", "not_declared")


def test_t16_dense_ledger_is_bounded():
    n = 150
    execs = [X(f"ex_{i:03d}", i + 1, produced=[f"v{i}"], consumed=[(f"v{j}", f"ex_{j:03d}") for j in range(i)])
             for i in range(n)]
    a, b = FD("A", ["ex_000"]), FD("B", [f"ex_{n - 1:03d}"], ["A"], push_seq=10_000)
    t0 = _time.perf_counter()
    state, reason, _ = ev.verify_edge(a, b, execs)
    assert _time.perf_counter() - t0 < 5.0
    assert state == "observed_flow"


def test_t17_evidence_refs_shape():
    state, reason, refs = ev.verify_edge(FA, FB, BASE)
    assert refs == {"executions": ["ex_a", "ex_b"], "value_fp": V[:12], "hops": 1, "negative_control": None}
    # a located failing chain keeps its refs
    led = BASE + [X("ex_x", 2, produced=[V])]
    state, reason, refs = ev.verify_edge(FA, FB, led)
    assert (state, reason) == ("declared_unverified", "ambiguous_origin")
    assert refs == {"executions": ["ex_a", "ex_b"], "value_fp": V[:12], "hops": 1}
    # an unlocated failure has no refs
    assert ev.verify_edge(FA, FB, [BASE[0], dict(BASE[1], consumed=[])])[2] == {}
    # two hops: the chain from e_a to e_b in order
    led2 = [X("ex_a", 1, produced=[V]), X("ex_m", 2, consumed=[(V, "ex_a")], produced=[W]),
            X("ex_b", 3, consumed=[(W, "ex_m")])]
    refs2 = ev.verify_edge(FA, FB, led2)[2]
    assert refs2["executions"] == ["ex_a", "ex_m", "ex_b"] and refs2["hops"] == 2 and refs2["value_fp"] == V[:12]


def test_t18_depth_beyond_three_is_depth_exceeded_within_the_search_bound():
    for links in (4, 5, 12):
        execs = [X(f"ex_{i:02d}", i + 1, produced=[f"h{i}"], consumed=[(f"h{i - 1}", f"ex_{i - 1:02d}")] if i else [])
                 for i in range(links + 1)]
        a, b = FD("A", ["ex_00"]), FD("B", [f"ex_{links:02d}"], ["A"])
        assert sr(a, b, execs) == ("declared_unverified", "depth_exceeded"), links
    execs = [X(f"ex_{i:02d}", i + 1, produced=[f"h{i}"], consumed=[(f"h{i - 1}", f"ex_{i - 1:02d}")] if i else [])
             for i in range(4)]
    assert sr(FD("A", ["ex_00"]), FD("B", ["ex_03"], ["A"]), execs) == ("observed_flow", None)


def test_t19_failing_chains_report_the_chain_that_got_furthest():
    """No valid chain: the reason is the one of the chain that passed the most checks (depth < origin < exogeneity <
    outcome); with one valid chain among failing ones: observed_flow."""
    base = [X("ex_a", 1, produced=[V, W]), X("ex_x", 2, produced=[W])]
    b_amb = X("ex_b1", 4, consumed=[(W, "ex_a")])                                       # ambiguous (ex_x)
    b_ref = X("ex_b2", 5, consumed=[(V, "ex_a")], outcome="refused", basis="http_refused")  # consumer_not_success
    b_ok = X("ex_b3", 6, consumed=[(V, "ex_a")])
    led = base + [b_amb, b_ref, b_ok]
    for ids in (["ex_b1", "ex_b2"], ["ex_b2", "ex_b1"]):
        assert sr(FA, FD("B", ids, ["A"]), led) == ("declared_unverified", "consumer_not_success"), ids
    assert sr(FA, FD("B", ["ex_b1", "ex_b2", "ex_b3"], ["A"]), led) == ("observed_flow", None)
    assert sr(FA, FD("B", ["ex_b3", "ex_b1"], ["A"]), led) == ("observed_flow", None)
    # exogenous (rank 2) beats ambiguous (rank 1); depth (rank 0) loses to both
    exo = [X("ex_p", 1, presented=[V]), X("ex_a", 2, produced=[V, W]), X("ex_x", 3, produced=[W]),
           X("ex_b1", 5, consumed=[(W, "ex_a")]), X("ex_b2", 6, consumed=[(V, "ex_a")])]
    for ids in (["ex_b1", "ex_b2"], ["ex_b2", "ex_b1"]):
        assert sr(FA, FD("B", ids, ["A"]), exo) == ("declared_unverified", "exogenous_value"), ids
    # consumer_not_success (rank 3) beats exogenous (rank 2), whatever the order the chains are found in
    exo2 = [X("ex_p", 1, presented=[W]), X("ex_a", 2, produced=[V, W]),
            X("ex_b1", 5, consumed=[(W, "ex_a")]),
            X("ex_b2", 6, consumed=[(V, "ex_a")], outcome="refused", basis="http_refused")]
    for ids in (["ex_b1", "ex_b2"], ["ex_b2", "ex_b1"]):
        assert sr(FA, FD("B", ids, ["A"]), exo2) == ("declared_unverified", "consumer_not_success"), ids
    exo3 = [X("ex_p", 1, presented=[V]), X("ex_a", 2, produced=[V, W]),
            X("ex_b", 5, consumed=[(V, "ex_a"), (W, "ex_a")], outcome="unknown", basis="none")]
    assert sr(FA, FB, exo3) == ("declared_unverified", "consumer_not_success")
    deep = [X(f"ex_{i:02d}", i + 1, produced=[f"h{i}"], consumed=[(f"h{i - 1}", f"ex_{i - 1:02d}")] if i else [])
            for i in range(6)]
    deep += [X("ex_00b", 10, consumed=[("h0", "ex_00")]), X("ex_y", 8, produced=["h0"])]
    for ids in (["ex_05", "ex_00b"], ["ex_00b", "ex_05"]):
        assert sr(FD("A", ["ex_00"]), FD("B", ids, ["A"]), deep) == ("declared_unverified", "ambiguous_origin"), ids


def test_t9_weakest_valid_chain_decides_and_its_refs_are_returned():
    eb = X("ex_b", 5, consumed=[(V, "ex_a"), (W, "ex_a")], keys=["op:v", "op:w"], ckeys=[["op:v"], ["op:w"]])
    ea = X("ex_a", 1, produced=[V, W])
    for ctl_on, weak_fp in (("op:w", V), ("op:v", W)):
        led = [ea, X("ex_c", 2, outcome="refused", basis="http_refused", keys=[ctl_on]), eb]
        state, reason, refs = ev.verify_edge(FA, FB, led)
        assert (state, reason) == ("observed_flow", None), ctl_on
        assert refs["value_fp"] == weak_fp[:12] and refs["negative_control"] is None
    both = [ea, X("ex_c1", 2, outcome="refused", basis="http_refused", keys=["op:v"]),
            X("ex_c2", 3, outcome="refused", basis="http_refused", keys=["op:w"]), eb]
    state, _, refs = ev.verify_edge(FA, FB, both)
    assert state == "causal_necessity_demonstrated" and refs["negative_control"] in ("ex_c1", "ex_c2")


def test_t7_t8_control_only_on_the_consuming_exchange_operation():
    ea = X("ex_a", 1, produced=[V])
    ctl_login = X("ex_c", 2, outcome="refused", basis="http_refused", keys=["op:login"])
    eb7 = X("ex_b", 3, consumed=[(W, "ex_a"), (V, "ex_a")], keys=["op:login", "op:users"],
            ckeys=[["op:login"], ["op:users"]])
    assert sr(FA, FB, [ea, ctl_login, eb7]) == ("observed_flow", None)
    eb8 = X("ex_b", 3, consumed=[(V, "ex_a")], keys=["op:login", "op:users"], ckeys=[["op:users"]])
    assert sr(FA, FB, [ea, ctl_login, eb8]) == ("observed_flow", None)
    eb_unknown = X("ex_b", 3, consumed=[(V, "ex_a")], keys=["op:login", "op:users"])
    assert sr(FA, FB, [ea, ctl_login, eb_unknown]) == ("observed_flow", None)
    ctl_users = X("ex_c", 2, outcome="refused", basis="http_refused", keys=["op:users"])
    assert sr(FA, FB, [ea, ctl_users, eb8])[0] == "causal_necessity_demonstrated"
    assert sr(FA, FB, [ea, ctl_users, eb_unknown]) == ("observed_flow", None)
    # no operation at all: never a control
    assert sr(FA, FB, [ea, dict(ctl_users, operation_keys=[]), X("ex_b", 3, consumed=[(V, "ex_a")], keys=[])]) == \
        ("observed_flow", None)


def test_t20_success_without_the_value_is_listed_and_blocks():
    led = BASE + [X(f"ex_s{i}", 2, keys=["op:b"]) for i in range(6)] + \
        [X("ex_r", 2, outcome="refused", basis="http_refused"), X("ex_cl", 2, basis="none")]
    state, _, refs = ev.verify_edge(FA, FB, led)
    assert state == "observed_flow"
    assert refs["negative_control"] is None
    assert refs["succeeded_without_value"] == ["ex_s0", "ex_s1", "ex_s2", "ex_s3"]
    # a success CLAIMED without a success basis still blocks, but is not listed as a success
    led2 = BASE + [X("ex_r", 2, outcome="refused", basis="http_refused"), X("ex_cl", 2, basis="none")]
    state, _, refs = ev.verify_edge(FA, FB, led2)
    assert state == "observed_flow" and refs["succeeded_without_value"] == []
    # an execution presenting the value is no control and no blocker
    led3 = BASE + [X("ex_r", 2, outcome="refused", basis="http_refused"), X("ex_p", 2, presented=[V])]
    assert ev.verify_edge(FA, FB, led3)[2]["negative_control"] == "ex_r"


def test_negative_control_is_the_earliest_refusal_and_needs_a_refusal_basis():
    led = BASE + [X("ex_r2", 2, outcome="refused", basis="refusal_signature"),
                  X("ex_r1", 0, outcome="refused", basis="http_refused"),
                  X("ex_nz", 1, outcome="refused", basis="exit_nonzero")]
    assert ev.verify_edge(FA, FB, led)[2]["negative_control"] == "ex_r1"
    only_nz = BASE + [X("ex_nz", 2, outcome="refused", basis="exit_nonzero")]
    assert sr(FA, FB, only_nz) == ("observed_flow", None)


def test_compacted_records_never_demonstrate_necessity():
    ctl = X("ex_c", 2, outcome="refused", basis="http_refused")
    assert sr(FA, FB, BASE + [ctl])[0] == "causal_necessity_demonstrated"
    for flag in (True, 1, "yes"):
        state, reason, refs = ev.verify_edge(FA, FB, BASE + [dict(ctl, run_compacted=flag)])
        assert (state, reason) == ("observed_flow", None)
        assert refs == {"executions": ["ex_a", "ex_b"], "value_fp": V[:12], "hops": 1, "negative_control": None}
    assert sr(FA, FB, [dict(BASE[0], run_compacted=True), BASE[1], ctl]) == ("observed_flow", None)
    for flag in (False, None, 0, ""):
        assert sr(FA, FB, BASE + [dict(ctl, run_compacted=flag)])[0] == "causal_necessity_demonstrated"


def test_findings_and_records_without_run_id():
    assert sr(FA, FD("B", ["ex_b"], ["A"], run=None), BASE) == ("declared_unverified", "cross_run")
    assert sr(FD("A", ["ex_a"], run=None), FD("B", ["ex_b"], ["A"], run=None), BASE) == ("declared_unverified", "cross_run")
    assert sr(FD("A", ["ex_a"], run=None), FB, BASE) == ("declared_unverified", "cross_run")
    runless = [{k: v for k, v in e.items() if k != "run_id"} for e in BASE]
    assert sr(FA, FB, runless) == ("declared_unverified", "unknown_execution")
    # run-less copies never validate, but still weaken (a run-less producer of v before e_b = ambiguity)
    assert sr(FA, FB, BASE + [X("ex_z", 2, produced=[V], run=None)]) == ("declared_unverified", "ambiguous_origin")
    assert sr(FA, FB, [BASE[0], dict(BASE[1], run_id="R2")]) == ("declared_unverified", "cross_run")


def test_duplicate_and_dedup_rules():
    assert sr(FA, dict(FB, duplicate_of="Z"), BASE) == ("declared_unverified", "duplicate_finding")
    assert sr(dict(FA, duplicate_of="Z"), FB, BASE) == ("declared_unverified", "duplicate_finding")
    assert sr(dict(FA, dedup_key="k"), dict(FB, dedup_key="k"), BASE) == ("declared_unverified", "duplicate_finding")
    for ka, kb in (("k1", "k2"), ("k1", None), (None, "k2"), ("", ""), (None, None)):
        assert sr(dict(FA, dedup_key=ka), dict(FB, dedup_key=kb), BASE) == ("observed_flow", None), (ka, kb)
    assert sr(FA, dict(FB, duplicate_of=""), BASE) == ("observed_flow", None)


def test_ledger_shapes():
    assert sr(FA, FB, {"executions": BASE}) == ("observed_flow", None)
    assert sr(FA, FB, tuple(BASE)) == ("observed_flow", None)
    for empty in (None, [], {}, {"executions": None}):
        assert sr(FA, FB, empty) == ("declared_unverified", "unknown_execution")
    assert sr(FA, FB, BASE + ["junk", None, {"no": "id"}]) == ("observed_flow", None)


# ------------------------------------------------------------------------------------- ledger lines -> records
FOK = ["h", "GET", "/users", 200, 1, "ok"]
LOGIN = ["h", "POST", "/login", 200, 1, "ok"]
LA, LB = FD("A", ["ex_aa"]), FD("B", ["ex_bb"], ["A"])


def L(cx, seq, ex=None, **kw):
    d = {"cx": cx, "seq": seq, "t": seq, "p": [], "c": [], "i": []}
    if ex is not None:
        d["ex"] = ex
    d.update(kw)
    return d


def P1(**kw):
    """e_a: login returns V (2xx)."""
    return L("c1", 1, "aa", p=[[V, "jwt"]], e=[LOGIN], **kw)


def C2(seq=3, ex="bb", **kw):
    """e_b: presents V from c1 on GET /users."""
    d = dict(c=[[V, "c1", "jwt"]], i=[V], e=[FOK])
    d.update(kw)
    return L("c2", seq, ex, **d)


def lsr(lines, a=LA, b=LB, run=RUN):
    return sr(a, b, {"executions": ev.executions_from_lines(lines, run)})


def test_execution_ref():
    assert ev.execution_ref("aa") == "ex_aa"
    assert ev.execution_ref("ex_aa") == "ex_aa"
    assert ev.execution_ref("  aa ") == "ex_aa"
    for blank in (None, "", "   ", 0):
        assert ev.execution_ref(blank) is None
    assert ev.execution_ref(12) == "ex_12"


def test_record_shape_is_the_contract():
    lines = [L("c1", 1, "aa", p=[[V, "jwt"], [V, "other"], [W, "file-ref"]], e=[LOGIN], ses="s1", t="T1",
               k=["svc-a"]),
             L("c2", 3, "bb", c=[[V, "c1", "jwt"], [W, "c1", "file-ref"]], i=[W, V], e=[FOK], ses=None, t="T3"),
             L("c3", 4, "bb", src="pcap", e=[["h", "GET", "/other", 404, 1, "x"]], t="T4", ses="s9")]
    recs = ev.executions_from_lines(lines, RUN)
    assert recs == [
        {"execution_id": "ex_aa", "run_id": RUN, "seq": 1, "t": "T1", "session": "s1",
         "produced": [{"fp": V, "kind": "jwt"}, {"fp": W, "kind": "file-ref"}], "consumed": [], "presented": [],
         "outcome": "success", "outcome_basis": "http_2xx", "operation_keys": ["http|h|POST|/login", "svc|svc-a"],
         "run_compacted": False},
        {"execution_id": "ex_bb", "run_id": RUN, "seq": 3, "t": "T3", "session": None, "produced": [],
         "consumed": [{"fp": V, "producer_execution_id": "ex_aa", "operation_keys": ["http|h|GET|/users"]},
                      {"fp": W, "producer_execution_id": "ex_aa", "operation_keys": ["http|h|GET|/users"]}],
         "presented": sorted([V, W]), "outcome": "success", "outcome_basis": "http_2xx",
         "operation_keys": ["http|h|GET|/users", "http|h|GET|/other"], "run_compacted": False},
    ]
    assert ev.executions_from_lines([], RUN) == [] and ev.executions_from_lines(None, RUN) == []


def test_t21_bad_lines_are_skipped_never_stop_the_reading():
    lines = ["junk", None, L("cx0", 0, "zz", x=False, p=[[V, "jwt"]]), P1(),
             L("c9", 2, "nn", e=[{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}, ["short"], "eeeeee"]),
             C2(c=[["bad"], None, [V, "c1", "jwt"]])]
    recs = ev.executions_from_lines(lines, RUN)
    assert [r["execution_id"] for r in recs] == ["ex_aa", "ex_nn", "ex_bb"]
    assert recs[1]["outcome"] == "unknown" and recs[1]["operation_keys"] == []
    assert lsr(lines) == ("observed_flow", None)
    assert ev.executions_from_lines([L("", 1, "aa"), {"seq": 2}], RUN) == []


@pytest.mark.parametrize("status,ok", [(200, True), (204, True), (299, True), (300, False), (199, False),
                                       (500, False), (401, False), ("200", False)])
def test_t22_only_a_2xx_fact_labelled_ok_is_an_http_success(status, ok):
    lines = [P1(), C2(e=[["h", "GET", "/u", status, 1, "ok"]])]
    assert lsr(lines) == (("observed_flow", None) if ok else ("declared_unverified", "consumer_not_success"))
    lines = [P1(), C2(e=[["h", "GET", "/u", 200, 1, "error"]])]
    assert lsr(lines) == ("declared_unverified", "consumer_not_success")


def test_t23_recorded_outcome_wins_over_legacy_fields():
    rec = C2(e=[], rc=0, o="ok", p=[[W, "s"]], oc="unknown", ob="none")
    assert lsr([P1(), rec]) == ("declared_unverified", "consumer_not_success")
    assert lsr([P1(), C2(e=[], oc="success", ob="exit0_expected_output")]) == ("observed_flow", None)
    # an out-of-enum recorded pair is not trusted: legacy mapping applies
    assert lsr([P1(), C2(e=[], oc="success", ob="magic", rc=0, o="ok", p=[[W, "s"]])]) == ("observed_flow", None)
    assert lsr([P1(), C2(e=[], oc="great", ob="http_2xx")]) == ("declared_unverified", "consumer_not_success")
    recs = ev.executions_from_lines([L("c5", 1, "q", oc="refused", ob="refusal_signature")], RUN)
    assert (recs[0]["outcome"], recs[0]["outcome_basis"]) == ("refused", "refusal_signature")


@pytest.mark.parametrize("fields,ok", [
    ({"o": "ok", "p": [[W, "secret"]]}, False),                         # no rc: never exit 0
    ({"rc": 0, "o": "error", "p": [[W, "s"]]}, False),
    ({"rc": 0, "o": "ok", "p": [[W, "file-ref"]]}, False),
    ({"rc": 0, "o": "ok", "p": []}, False),
    ({"rc": 0, "o": "ok", "p": [[W]]}, False),
    ({"rc": "0", "o": "ok", "p": [[W, "s"]]}, False),
    ({"rc": 1, "o": "ok", "p": [[W, "s"]]}, False),
    ({"rc": 0, "o": "ok", "p": [[W, "s"]]}, True),
    ({"rc": 0, "o": "ok", "p": [[W, "file-ref"], [V, "jwt"]]}, True),
])
def test_t24_legacy_exit_zero_needs_ok_and_a_real_output(fields, ok):
    lines = [P1(), C2(e=[], **fields)]
    assert lsr(lines) == (("observed_flow", None) if ok else ("declared_unverified", "consumer_not_success"))


def test_t24_legacy_outcome_labels():
    one = lambda **kw: ev.executions_from_lines([L("c5", 1, "q", **kw)], RUN)[0]  # noqa: E731
    r = one(rc=3, o="ok", p=[[W, "s"]])
    assert (r["outcome"], r["outcome_basis"]) == ("unknown", "exit_nonzero")
    r = one(rc=0, o="ok", p=[[W, "s"]])
    assert (r["outcome"], r["outcome_basis"]) == ("success", "exit0_expected_output")
    r = one(rc=0, o="ok", p=[[W, "file-ref"]])
    assert (r["outcome"], r["outcome_basis"]) == ("unknown", "none")
    r = one(o="refused", os="sig")
    assert (r["outcome"], r["outcome_basis"]) == ("refused", "refusal_signature")
    r = one(rc=1, o="refused", os="sig")
    assert (r["outcome"], r["outcome_basis"]) == ("refused", "refusal_signature")
    r = one(o="refused")
    assert (r["outcome"], r["outcome_basis"]) == ("unknown", "none")
    r = one(o="ok", os="sig", rc=0)
    assert (r["outcome"], r["outcome_basis"]) == ("unknown", "none")


def test_t25_legacy_refusal_needs_o_refused_and_a_signature():
    ctl_ok = L("c3", 2, "cc", rc=0, o="ok", os="sig", k=["login"])
    ctl_ref = L("c3", 2, "cc", o="refused", os="sig", k=["login"])
    ctl_nosig = L("c3", 2, "cc", o="refused", k=["login"])
    for ctl, want in ((ctl_ok, "observed_flow"), (ctl_nosig, "observed_flow"),
                      (ctl_ref, "causal_necessity_demonstrated")):
        assert lsr([P1(), ctl, C2(k=["login"], e=[])][:3] if False else
                   [P1(), ctl, C2(k=["login"], e=[], rc=0, o="ok", p=[[W, "s"]])])[0] == want, ctl


@pytest.mark.parametrize("fact,causal", [
    (["h", "GET", "/users", 401, 1, "refused"], True),
    (["h", "GET", "/users", 403, 0, "refused"], True),
    (["other", "GET", "/users", 401, 1, "refused"], False),
    (["h", "DELETE", "/users", 401, 1, "refused"], False),
    (["h", "GET", "/users2", 401, 1, "refused"], False),
    (["h", "GET", "/users", 401, 1, "error"], False),
])
def test_t26_t27_http_operation_key_is_host_method_path(fact, causal):
    lines = [P1(), L("c3", 2, "cc", e=[fact]), C2()]
    assert lsr(lines)[0] == ("causal_necessity_demonstrated" if causal else "observed_flow")


def test_t27_service_keys():
    ctl = L("c3", 2, "cc", k=["redis|h|6379"], o="refused", os="NOAUTH")
    use = C2(e=[], k=["redis|h|6379"], rc=0, o="ok", p=[[W, "s"]])
    assert lsr([P1(), ctl, use])[0] == "causal_necessity_demonstrated"
    other = L("c3", 2, "cc", k=["redis|h|6380"], o="refused", os="NOAUTH")
    assert lsr([P1(), other, use])[0] == "observed_flow"
    recs = ev.executions_from_lines([use], RUN)
    assert recs[0]["operation_keys"] == ["svc|redis|h|6379"]


def test_t28_execution_ids_from_ex_and_ex_less_lines():
    lines = [L("c1", 1, "ex_aa", p=[[V, "jwt"]], e=[LOGIN]), C2(ex="ex_bb")]
    assert lsr(lines) == ("observed_flow", None)
    # lines without ex stand alone under their cx: two of them are two records, never merged
    loose = [L("c1", 1, p=[[V, "jwt"]], e=[LOGIN]), L("c2", 2, c=[[V, "c1", "jwt"]], i=[V], e=[FOK]),
             L("c3", 3, ex="", e=[["h", "GET", "/u", 500, 1, "x"]])]
    recs = ev.executions_from_lines(loose, RUN)
    assert [r["execution_id"] for r in recs] == ["c1", "c2", "c3"]
    for a_ids, b_ids in ((["ex_XXXX"], ["None"]), (["ex_None"], ["ex_None"]), (["XXXX"], ["ex_"])):
        assert lsr(loose, FD("A", a_ids), FD("B", b_ids, ["A"]))[1] == "unknown_execution"


def test_t29_contract_shaped_lines_keep_their_run():
    other = dict(X("ex_a", 1, produced=[V], keys=["op:a"]), run_id="R2")
    recs = ev.executions_from_lines([other, X("ex_b", 3, consumed=[(V, "ex_a")])], RUN)
    assert [r["run_id"] for r in recs] == ["R2", RUN]
    assert sr(FA, FB, {"executions": recs}) == ("declared_unverified", "cross_run")
    # a contract-shaped line without run_id takes the ledger's run (it is in that run's file)
    runless = {k: v for k, v in BASE[0].items() if k != "run_id"}
    recs = ev.executions_from_lines([runless, BASE[1]], RUN)
    assert [r["run_id"] for r in recs] == [RUN, RUN]
    assert sr(FA, FB, {"executions": recs}) == ("observed_flow", None)
    # read without a run: never evidence for any run
    recs = ev.executions_from_lines([runless, {k: v for k, v in BASE[1].items() if k != "run_id"}], None)
    assert [r["run_id"] for r in recs] == [None, None]
    assert sr(FA, FB, {"executions": recs}) == ("declared_unverified", "unknown_execution")
    # ledger lines of two runs read per run and merged: run-2 records never prove a run-1 edge
    r1 = ev.executions_from_lines([P1()], RUN)
    r2 = ev.executions_from_lines([L("c1", 1, "aa2", p=[[V, "jwt"]], e=[LOGIN]), C2()], "R2")
    assert all(r["run_id"] == "R2" for r in r2)
    assert sr(LA, LB, {"executions": r1 + r2})[1] in ("cross_run",)
    assert sr(FD("A", ["ex_aa2"], run="R2"), FD("B", ["ex_bb"], ["A"], run="R2"), {"executions": r1 + r2}) == \
        ("observed_flow", None)


def test_t30_lines_flagged_not_executed_are_no_executions():
    assert lsr([P1(), C2(x=False)]) == ("declared_unverified", "unknown_execution")
    assert lsr([P1(x=False), C2()]) == ("declared_unverified", "unknown_execution")
    assert lsr([P1(x=True), C2(x=None)]) == ("observed_flow", None)
    # a not-executed line inside an execution's group is ignored, the execution stays
    lines = [P1(), L("c2x", 2, "bb", x=False, e=[["h", "GET", "/u", 500, 1, "x"]]), C2()]
    recs = ev.executions_from_lines(lines, RUN)
    assert [r["seq"] for r in recs] == [1, 3]
    assert lsr(lines) == ("observed_flow", None)


def test_t31_exchange_only_execution_is_dated_by_its_latest_line():
    lines = [P1(), L("c2", 2, "bb", src="pcap", c=[[V, "c1", "jwt"]], i=[V], e=[FOK]),
             L("c5", 9, "bb", src="pcap", e=[FOK])]
    recs = ev.executions_from_lines(lines, RUN)
    assert recs[1]["seq"] == 9
    assert lsr(lines, LA, FD("B", ["ex_bb"], ["A"], push_seq=5)) == ("declared_unverified", "execution_after_push")
    assert lsr(lines, LA, FD("B", ["ex_bb"], ["A"], push_seq=10)) == ("observed_flow", None)
    # odd shapes never raise: no seq, seq None, exchange lines only without seq
    odd = [L("c7", None, "q1", src="tap"), {"cx": "c8", "ex": "q2", "src": "tap"}, L("c9", 0, "q3"),
           {"cx": "c10", "ex": "q4", "seq": 5, "c": [[V, "nobody"]], "e": [FOK]}]
    recs = ev.executions_from_lines(odd, RUN)
    assert [r["seq"] for r in recs] == [0, 0, 0, 5] and recs[3]["consumed"] == []
    # the command line dates its execution even when exchanges come later
    cmd_then_ex = [L("c7", 2, "pp", p=[[V, "jwt"]], rc=0, o="ok"), L("c8", 6, "pp", src="pcap", e=[FOK])]
    assert ev.executions_from_lines(cmd_then_ex, RUN)[0]["seq"] == 2
    # several command lines: the last one is the head
    two_cmds = [L("c7", 2, "pp", rc=1), L("c8", 4, "pp", rc=0, o="ok", p=[[W, "s"]], t="T4", ses="s4"),
                L("c9", 7, "pp", src="pcap")]
    r = ev.executions_from_lines(two_cmds, RUN)[0]
    assert (r["seq"], r["t"], r["session"], r["outcome"]) == (4, "T4", "s4", "success")


def test_t32_one_execution_with_a_refusal_and_a_success_is_a_success():
    lines = [P1(), L("c3", 2, "cc", src="pcap", e=[["h", "GET", "/users", 401, 1, "refused"]]),
             L("c4", 3, "cc", src="pcap", e=[FOK]), C2(seq=4)]
    recs = ev.executions_from_lines(lines, RUN)
    assert (recs[1]["outcome"], recs[1]["outcome_basis"]) == ("success", "http_2xx")
    assert lsr(lines) == ("observed_flow", None)
    order2 = [lines[0], lines[2], lines[1], lines[3]]
    assert lsr(order2) == ("observed_flow", None)
    refused_only = [P1(), lines[1], C2(seq=4)]
    assert lsr(refused_only)[0] == "causal_necessity_demonstrated"


def test_t33_competing_producer_is_dated_by_its_command():
    lines = [P1(), L("c7", 2, "pp", p=[[V, "jwt"]], rc=0, o="ok"), C2(seq=5),
             L("c8", 6, "pp", src="pcap", e=[FOK])]
    assert lsr(lines) == ("declared_unverified", "ambiguous_origin")


def test_t34_operation_keys_of_every_line_of_an_execution():
    lines = [P1(), L("c3", 2, "cc", e=[FOK]), L("c3b", 3, "cc", src="pcap", e=[["h", "GET", "/other", 404, 1, "x"]]),
             L("c4", 4, "dd", e=[["h", "GET", "/users", 401, 1, "refused"]]), C2(seq=5)]
    state, _, refs = ev.verify_edge(LA, LB, {"executions": ev.executions_from_lines(lines, RUN)})
    assert state == "observed_flow" and refs["succeeded_without_value"] == ["ex_cc"]
    recs = ev.executions_from_lines(lines, RUN)
    assert recs[1]["operation_keys"] == ["http|h|GET|/users", "http|h|GET|/other"]
    # a key already seen on an earlier line of the execution is not repeated
    dup = ev.executions_from_lines([L("c3", 2, "cc", e=[FOK]), L("c3b", 3, "cc", src="p", e=[FOK])], RUN)
    assert dup[0]["operation_keys"] == ["http|h|GET|/users"]


def test_t35_presented_values_make_a_value_exogenous():
    lines = [L("c0", 0, "zz", i=[V], rc=0, o="ok"), P1(), C2()]
    assert lsr(lines) == ("declared_unverified", "exogenous_value")
    lines = [P1(i=[V]), C2()]
    assert lsr(lines) == ("declared_unverified", "exogenous_value")
    # presented on a later exchange line of the producer's own execution counts too
    lines = [P1(), L("c1b", 1, "aa", src="pcap", i=[V], e=[LOGIN]), C2()]
    assert lsr(lines) == ("declared_unverified", "exogenous_value")
    recs = ev.executions_from_lines([L("c0", 0, "zz", i=[W, V]), L("c0b", 1, "zz", src="p", i=[V])], RUN)
    assert recs[0]["presented"] == sorted([V, W])


def test_t36_first_attribution_of_a_value_in_an_execution_is_kept():
    lines = [L("c0", 1, "zz", rc=0, o="ok"), L("c1", 2, "aa", p=[[V, "jwt"]], e=[FOK]),
             L("c2", 3, "bb", src="pcap", c=[[V, "c0", "jwt"]], i=[V], e=[FOK]),
             L("c2b", 4, "bb", src="pcap", c=[[V, "c1", "jwt"]], i=[V], e=[FOK])]
    assert lsr(lines)[0] == "declared_unverified"
    recs = ev.executions_from_lines(lines, RUN)
    assert recs[2]["consumed"] == [{"fp": V, "producer_execution_id": "ex_zz", "operation_keys": ["http|h|GET|/users"]}]
    # a consumption naming an unknown cx or the execution itself is not a consumption
    self_use = ev.executions_from_lines([L("c1", 1, "aa", p=[[V, "jwt"]]),
                                        L("c1b", 2, "aa", c=[[V, "c1", "jwt"], [W, "cx_unknown"]])], RUN)
    assert self_use[0]["consumed"] == []


def test_producer_recording_the_value_as_its_own_input_did_not_originate_it():
    self_in = [X("ex_a", 1, produced=[V], consumed=[(V, "ex_a")]), BASE[1]]
    assert sr(FA, FB, self_in) == ("declared_unverified", "exogenous_value")
    pres = [X("ex_a", 1, produced=[V], presented=[V]), BASE[1]]
    assert sr(FA, FB, pres) == ("declared_unverified", "exogenous_value")


def test_two_element_consumption_entries_are_read():
    lines = [P1(), C2(c=[[V, "c1"]])]
    recs = ev.executions_from_lines(lines, RUN)
    assert recs[1]["consumed"] == [{"fp": V, "producer_execution_id": "ex_aa", "operation_keys": ["http|h|GET|/users"]}]
    assert lsr(lines) == ("observed_flow", None)
    assert ev.executions_from_lines([P1(), C2(c=[[V]])], RUN)[1]["consumed"] == []


def test_t37_an_http_refusal_is_decisive_over_the_command():
    lines = [P1(), L("c2", 2, "bb", src="pcap", c=[[V, "c1", "jwt"]], i=[V], e=[["h", "GET", "/u", 401, 1, "refused"]]),
             L("c2b", 3, "bb", rc=0, o="ok", p=[[W, "s"]])]
    recs = ev.executions_from_lines(lines, RUN)
    assert (recs[1]["outcome"], recs[1]["outcome_basis"]) == ("refused", "http_refused")
    assert lsr(lines) == ("declared_unverified", "consumer_not_success")
    # without HTTP facts the command's own outcome decides
    lines = [P1(), L("c2", 2, "bb", c=[[V, "c1", "jwt"]], i=[V], rc=0, o="ok", p=[[W, "s"]])]
    assert lsr(lines) == ("observed_flow", None)


def test_compaction_marks_every_record_of_the_run():
    lines = _necessity_lines(True)
    recs = ev.executions_from_lines(lines, "R1")
    assert recs and all(r["run_compacted"] is True for r in recs)
    assert all(r["run_compacted"] is False for r in ev.executions_from_lines(_necessity_lines(False), "R1"))
    junk_first = ["junk"] + _necessity_lines(True)
    assert all(r["run_compacted"] is True for r in ev.executions_from_lines(junk_first, "R1"))
