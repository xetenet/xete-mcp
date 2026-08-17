"""SPEC-mcp-prompts-resources-20260817."""
import json
from pathlib import Path

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


def test_spend_limits_reports_json_even_when_spendguard_raises(monkeypatch):
    # Mirrors what a real spendguard.status() failure embeds (server.py's own
    # _scrub_paths docstring: "the home directory is in it, so the OS username is in
    # it") — using an unrelated fake path here would pass without exercising the real
    # redaction logic at all, which only scrubs Path.home() and the configured ledger.
    from xete_mcp import spendguard

    home = str(Path.home())

    def boom():
        raise RuntimeError(f"{home}/.xete/spend-ledger.json is corrupt")

    monkeypatch.setattr(spendguard, "status", boom)
    data = json.loads(resources.spend_limits())
    assert data.get("enforced") is True
    assert "error" in data
    # _scrub_paths must still have run on the exception's own message.
    assert home not in data["error"]


def test_safety_model_is_byte_identical_to_readme():
    # DDR finding (reviews/DDR-mcp-prompts-resources-20260817.md, doubt #5): the spec
    # claims this can't silently drift from README.md, but nothing enforced that until
    # this test. The wheel doesn't ship README.md (see resources.py's module
    # docstring), so this only runs against a source checkout — exactly where an editor
    # would actually change the README section and need to be told the copy broke.
    readme = Path(__file__).parent / "README.md"
    text = readme.read_text(encoding="utf-8")
    start = text.index("## The safety model — draft, verify, then sign")
    end = text.index("## Install")
    section = text[start:end].rstrip("\n") + "\n"
    assert resources.SAFETY_MODEL_MARKDOWN == section, (
        "resources.SAFETY_MODEL_MARKDOWN has drifted from README.md's safety-model "
        "section — update the hand-maintained copy in resources.py to match")
