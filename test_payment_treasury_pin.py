"""Pin the payment destination, because nothing else in this package would notice it changing.

The program pins its payment destination and rejects any transaction naming a different account,
so this constant is not a preference — it must match the deployed program exactly or every
payment this package builds is refused.

Two properties make that worth a test rather than a code review:

1. **base58 has no checksum.** Transpose two characters and the result is still a syntactically
   valid 32-byte key. There is no parse error to catch it, no runtime warning, and the failure
   surfaces only as every user's payments being rejected.
2. **A raw 32-byte value is unreviewable by eye.** The program keeps the same invariant on its own
   side for the same reason, and the alias path keeps one for its treasury. The payment path was
   the gap.

Superficially this test just restates a line of source. That is exactly the point: it restates it
in a second place, so a single-site edit cannot pass silently.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp.payment import PROGRAM_ID, TREASURY  # noqa: E402

# The destination the currently deployed program accepts.
EXPECTED_TREASURY = "DdcVGJcXBCZqRcMBCa6AyuKeF4pLop4NehSjkALN2SYh"
# The program this constant is paired with. A treasury is only correct with respect to a program,
# so pinning one without the other would let a mismatched pair pass.
EXPECTED_PROGRAM = "GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U"
# Destinations this package has used previously. Superseded; must not come back, including via a
# revert, a bad merge, or a cherry-pick from an older branch.
SUPERSEDED = ("XETEsj7sRmSQf1PHVU9FkmZW2n8z75UycWRrpJ8tRMv",)


def test_the_treasury_is_the_one_the_deployed_program_accepts():
    assert str(TREASURY) == EXPECTED_TREASURY, (
        f"payment destination is {TREASURY}, expected {EXPECTED_TREASURY}. If this was changed "
        f"deliberately, the deployed program must already accept the new value — otherwise every "
        f"payment this package builds will be rejected.")


def test_the_program_id_is_pinned_alongside_it():
    assert str(PROGRAM_ID) == EXPECTED_PROGRAM, (
        f"program id is {PROGRAM_ID}, expected {EXPECTED_PROGRAM}. The destination above is only "
        f"valid for that program.")


def test_a_superseded_destination_cannot_reappear():
    for old in SUPERSEDED:
        assert str(TREASURY) != old, (
            f"the payment destination reverted to a superseded value ({old}). Payments built "
            f"against it are rejected by the deployed program.")


def test_the_destination_parses_to_a_full_32_byte_key():
    """A truncated or padded value can still construct; length is the cheap independent check."""
    assert len(bytes(TREASURY)) == 32
