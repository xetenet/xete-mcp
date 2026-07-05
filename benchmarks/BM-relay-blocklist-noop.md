# BM: Blocklist check is an empty no-op and the send path has no rate limit
Source: xete-relay-clone culprit 8cfde150 fixed by c71cbc44
Paths: src/messaging/mod.rs (check_blocklist, send_wallet, send_multi_msg)
Class: validation-gap / DoS-flood
Catchable at commit time: yes
Gate mapping: security check whose body is empty/`{ /* ... */ }` or whose return value is discarded is a no-op — verify enforcement, not existence
Doubt prompt: `check_blocklist` ends with `if blocked > 0 { /* Silently drop */ }` and returns `()` — the caller ignores it. Does a blocked sender's message actually get dropped, and is there any per-sender/per-recipient send cap at all?
Real solution: Made `check_blocklist` return `bool`, silently ACK-and-drop blocked recipients (so block status can't be probed), and added per-sender (20) and per-(sender→recipient) (10) flood caps on both single and batch send.
