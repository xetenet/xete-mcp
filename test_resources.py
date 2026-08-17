"""SPEC-mcp-prompts-resources-20260817."""
import json

from xete_mcp import resources


def test_safety_model_is_nonempty_markdown_mentioning_the_real_tools():
    text = resources.safety_model()
    assert text.startswith("## The safety model")
    assert "xete_draft_settlement_tx" in text
    assert "xete_verify_settlement_tx" in text
    assert "What this does not solve" in text


def test_safety_model_names_no_spend_or_signing_call():
    text = resources.safety_model()
    for bad in ("Keypair(", "sign_message", "submit_transaction"):
        assert bad not in text


def test_spend_limits_returns_valid_json_without_absolute_ledger_path():
    raw = resources.spend_limits()
    data = json.loads(raw)
    assert data.get("enforced") is True
    assert "ledger" not in data  # popped by _redact_ledger_path, same as xete_my_identity
    if "ledger_file" in data:
        assert "/" not in data["ledger_file"] and "\\" not in data["ledger_file"]


def test_spend_limits_matches_spendguard_status_shape():
    from xete_mcp.spendguard import status

    live = status()
    reported = json.loads(resources.spend_limits())
    for key in ("per_transaction_max_lamports", "window_lamports", "window_seconds",
                "on_chain_floor_lamports"):
        assert reported.get(key) == live.get(key)
