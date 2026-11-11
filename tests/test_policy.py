from innovabank import policy

ME = {"customer_id": "C-1001", "email": "alex@customer.example", "payees": ["ACC-2001"]}


def controls(name, args, state=None):
    return {v.control for v in policy.evaluate(name, args, ME, state or policy.TurnState(), 1000.0)}


def test_own_account_read_is_allowed():
    assert controls("get_account_summary", {"customer_id": "C-1001"}) == set()


def test_cross_customer_read_is_denied():
    assert controls("get_account_summary", {"customer_id": "C-1002"}) == {"tool_policy"}


def test_transfer_to_registered_payee_within_limit_is_allowed():
    assert controls("transfer_funds", {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": 120}) == set()


def test_transfer_rules_each_fire():
    base = {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": 120}
    for change in ({"from_customer_id": "C-1002"}, {"to_account": "ATTACKER-999"}, {"amount": 5000}, {"amount": -1}):
        reasons = policy.evaluate("transfer_funds", {**base, **change}, ME, policy.TurnState(), 1000.0)
        assert reasons and all(v.control == "tool_policy" for v in reasons)


def test_message_only_to_address_on_file():
    ok = {"to_email": "ALEX@customer.example", "subject": "s", "body": "b"}
    assert controls("send_secure_message", ok) == set()
    bad = policy.evaluate("send_secure_message", {**ok, "to_email": "x@attacker.example"}, ME, policy.TurnState(), 1000.0)
    assert bad[0].ib_event == "exfiltration_attempt"


def test_document_reads_are_confined_to_the_public_prefix():
    assert controls("read_document", {"key": "kb/public/fees.md"}) == set()
    assert controls("read_document", {"key": "internal/ops-runbook.md"}) == {"tool_policy"}
    assert controls("read_document", {"key": "kb/public/../../internal/x"}) == {"tool_policy"}


def test_taint_locks_state_changing_tools_only():
    tainted = policy.TurnState(tainted=True)
    assert "taint_lock" in controls("transfer_funds", {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": 1}, tainted)
    assert "taint_lock" in controls("send_secure_message", {"to_email": "alex@customer.example", "subject": "s", "body": "b"}, tainted)
    assert controls("get_account_summary", {"customer_id": "C-1001"}, tainted) == set()


def test_budget_is_enforced_after_six_calls():
    assert controls("search_knowledge_base", {"query": "fees"}, policy.TurnState(tool_count=6)) == {"budget"}


def test_malformed_arguments_and_unknown_tools_are_rejected():
    assert controls("transfer_funds", {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": "lots"}) == {"tool_policy"}
    assert controls("transfer_funds", {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": True}) == {"tool_policy"}
    assert controls("delete_everything", {}) == {"tool_policy"}
