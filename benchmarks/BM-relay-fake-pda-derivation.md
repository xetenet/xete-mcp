# BM: Fake, hand-rolled PDA derivation + wrong RPC decoder can't verify real on-chain payments
Source: xete-relay-clone culprit 3b743202 fixed by 707a4adb
Paths: src/solana_rpc.rs (find_payment_pda, AccountContext decoder), src/messaging/mod.rs
Class: crypto / validation-gap
Catchable at commit time: yes
Gate mapping: NEW — never re-implement a cryptographic/protocol primitive by hand when a library implementation exists; any "rough heuristic / in production use the real check" comment is an automatic block
Doubt prompt: `find_payment_pda` hashes a domain marker at the START and checks `hash[0] < 128` as the curve test, with a comment saying "rough heuristic / in production use the actual curve check" — does this actually match Solana's `find_program_address`, or will it match/verify the wrong address?
Real solution: Rewrote derivation to match Solana's real seed/bump/program-id/marker order and used `ed25519_dalek::VerifyingKey::from_bytes` for the on-curve check; fixed the RPC JSON `context` wrapper so account deserialization works.
