# BM: Zero-amount and already-expired listings/bids accepted into the book
Source: xete-swap culprits 492ce966 (open_swap), 9a436a5ab (make_offer) fixed by dde75c585
Paths: src/lib.rs
Class: validation-gap
Catchable at commit time: yes
Gate mapping: input-validation — reject zero/degenerate economic amounts and timestamps already in the past at creation time
Doubt prompt: What happens if open_swap is called with give_amount=0 or want_amount=0, or with expiry <= now — can empty or born-dead listings (and zero-value offers) enter the order book, and what do downstream paths do with them?
Real solution: open_swap rejects give/want == 0 and expiry <= now; make_offer rejects want_amount == 0. Guard tests added.
