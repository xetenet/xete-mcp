# BM: PDA close+reopen rug — offer/fill settles against unpinned terms at a reused swap address
Source: xete-swap culprits 9a436a5ab, 492ce966 (boundary), 246e47624 fixed by dde75c585
Paths: src/lib.rs (open_swap/fill/make_offer/accept_offer), tests/swap_test.py
Class: replay
Catchable at commit time: yes
Gate mapping: account-revival / PDA-reuse — any state referenced by address must be re-validated against the terms agreed to, because a closed PDA can be recreated at the same address with different contents; takers/acceptors supply expected-terms (slippage) bounds
Doubt prompt: The offer stores only the swap PDA's *address* — if the maker cancels that swap and reopens the same nonce (same address) with give=1 instead of give=100, does accept_offer still settle the standing 300 bid? Same question for a fill landing after a same-slot close+reopen.
Real solution: Offer layout extended to record the listing's give_mint + give_amount at bid time; accept_offer rejects if the live listing no longer matches. fill takes expect_give/max_want from the taker and rejects mismatches. Adversarial rug/slippage tests added.
