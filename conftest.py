"""Make a bare `pytest` work from a clean checkout.

IT DID NOT, AND THAT MATTERED MORE THAN IT LOOKS. Three files at the repo root are named
`test_*.py` but are standalone integration SCRIPTS, not pytest tests. Two of them execute
their whole body at import and end with a module-level `sys.exit(...)`, which kills
pytest's COLLECTION phase outright: a bare `pytest` exited 3 with zero tests collected,
and the third needs a live relay on localhost.

So every "N tests passing" figure this project has quoted came from running an explicit
file list by hand. Nothing made the suite runnable by a machine, which is why no CI job
ran it -- and a suite nothing runs is a suite that stops being true without anyone
noticing. Found by an independent reviewer who went to verify a README claim and could not
start the tests at all.

These three stay as scripts (they are useful ones, and two genuinely need a live server),
but they are excluded from collection so `pytest` means the same thing for a human, for
CI, and for anyone auditing this package before installing it.
"""
collect_ignore = [
    # Executes 14 crypto assertions at import time, prints its own tally, then
    # `sys.exit(0)`. Run it directly: `python test_crypto_unification.py`.
    "test_crypto_unification.py",
    # Same shape, and additionally wants a relay at 127.0.0.1:8099.
    "test_rotation_live.py",
    # Needs a live server, and calls XeteClient with an argument set the client no longer
    # takes -- it raises at import even with a server up.
    "test_e2e.py",
]
