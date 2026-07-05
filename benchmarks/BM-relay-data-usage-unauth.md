# BM: /data-usage is unauthenticated and sums the entire messages table
Source: xete-relay-clone culprit d5eb9081 fixed by 6b47a5b9
Paths: src/system/mod.rs
Class: auth / info-disclosure + DoS
Catchable at commit time: yes
Gate mapping: new HTTP handler — is it authenticated and scoped to the caller's own data?
Doubt prompt: `data_usage` runs `SUM(LENGTH(encrypted_content)) FROM messages` with no auth extractor and no `WHERE recipient_id = ?` — what stops an anonymous caller from reading global storage and forcing a full-column scan on demand?
Real solution: Added `auth_wallet` gate and scoped the SUM to `recipient_id = <caller's agent_id>`.
