# BM: DB migration creates an index on a column before the ALTER that adds it — startup panic
Source: xete-relay-clone culprits 8cfde150, 7617fc1f fixed by 242a57bd
Paths: src/db.rs
Class: db-integrity / panic-DoS
Catchable at commit time: yes
Gate mapping: schema migration ordering — does every referenced column exist on the *old* prod schema before it is used?
Doubt prompt: `CREATE INDEX ... ON messages(payment_nonce)` runs inline, but the `ALTER TABLE ADD COLUMN payment_nonce` is elsewhere/missing — on a pre-existing prod DB without that column, does startup panic?
Real solution: Added the missing `ALTER TABLE ADD COLUMN` for `payment_status`/`payment_nonce` and moved the `CREATE INDEX` into the migration block after the ALTERs; tested on a copy of the live prod DB.
