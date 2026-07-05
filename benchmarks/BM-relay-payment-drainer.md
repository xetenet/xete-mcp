# BM: On-chain payment contract drains the payer's entire wallet on every call
Source: xete-relay-clone culprit b7abe8dd fixed by 707a4adb
Paths: contracts/xete_payment_detector/src/lib.rs
Class: logic / value-loss
Catchable at commit time: yes
Gate mapping: NEW — value transfer bounded and consented: the transferred amount must be a priced/invoice amount the caller agreed to, never a balance read
Doubt prompt: The transfer amount is `payer.lamports()` — the whole balance. Where is the invoice/price check that says this is the amount the user agreed to pay?
Real solution: Replaced the `transfer(payer.lamports())` drainer with a priced pay-per-herd contract (0.001 SOL/blob, max 100), Borsh instruction data, hardcoded XETE treasury, PDA-existence replay protection.
