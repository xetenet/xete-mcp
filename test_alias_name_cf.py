"""`AliasChainError`'s message is this client's own words, or its docstring is a lie.

FOUND BY AN INDEPENDENT REVIEW of the alias read path's prose-quarantine property. The
quarantine mechanism itself is sound -- attacker prose goes in `untrusted_server_text`
through `_quarantine()` at every consumer, and `sanitize_text` holds against newlines and
Cf. This is the OTHER half of that pair: the half a caller is told it may present
unattributed.

`normalize_name` rejects whitespace, C0 controls and 0x7F:

    ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F

Cf (format) characters satisfy NONE of those. Zero-width space, RTL override, word joiner
and soft hyphen all pass, and the RETURN value is then interpolated raw as `%{bare}` into
three error messages. `sanitize_text` is applied to the INPUT on the rejection branches and
never to the value that SURVIVES.

Bounded to 32 bytes with no whitespace, so it is not a channel for injected prose. The harm
is attribution and rendering: `%al<ZWSP>ice` renders as `%alice` in the sentence the agent
is told to trust, so an operator reading a failure cannot tell which name actually failed --
and U+202E reverses the rendering of the rest of the line in a terminal.

Fixed at the SOURCE rather than at the three interpolations. A name containing invisible
characters is not a name this registry can hold: `canonical_name` already enforces
[a-z0-9_], so nothing legitimate is lost, and rejecting it here means the next site that
interpolates `bare` inherits the guarantee instead of having to remember.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import alias_chain  # noqa: E402

CF = [("​", "ZERO WIDTH SPACE"), ("‮", "RTL OVERRIDE"),
      ("⁠", "WORD JOINER"), ("­", "SOFT HYPHEN")]


@pytest.mark.parametrize("ch,label", CF)
def test_a_format_character_is_not_a_name(ch, label):
    with pytest.raises(alias_chain.InvalidAliasName) as ei:
        alias_chain.normalize_name(f"al{ch}ice")
    assert ch not in str(ei.value), (
        f"{label}: the refusal ECHOED the character it is refusing, into a message the "
        f"caller is told is this client's own words")


@pytest.mark.parametrize("ch,label", CF)
def test_a_format_character_never_reaches_an_error_message(ch, label):
    """Driven through the REAL resolve path, not by re-typing the f-string.

    The reviewer's first pass reconstructed the interpolation by hand and threw it away --
    a code-reading claim wearing a repro's clothes. This calls the function.
    """
    with pytest.raises(alias_chain.AliasChainError) as ei:
        alias_chain.resolve_owner_at(f"al{ch}ice", rpc="http://127.0.0.1:9/")
    assert ch not in str(ei.value), (
        f"{label} survived into AliasChainError, whose docstring promises the message is "
        f"'this client's own words, end to end'")


def test_an_ordinary_name_still_normalises():
    """THE CONTROL. A normaliser that refuses real names is a worse defect than this one."""
    assert alias_chain.normalize_name("%Alice") == "alice"
    assert alias_chain.normalize_name("  bob_99 ") == "bob_99"
