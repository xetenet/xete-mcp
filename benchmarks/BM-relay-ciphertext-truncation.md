# BM: Inbox JSON API truncates E2E ciphertext to 200 chars, corrupting messages
Source: xete-relay-clone culprit 43bc51db fixed by d8e04eac
Paths: src/messaging/mod.rs (inbox_wallet serialization)
Class: message-integrity / data-corruption
Catchable at commit time: yes
Gate mapping: truncating/mutating a field that is opaque ciphertext, not display text — previews belong in the UI layer, never the API
Doubt prompt: `content` is E2E ciphertext but the inbox folder does `format!("{}...", &ct[..200])` — a preview transform on ciphertext makes it undecryptable (and `&ct[..200]` risks a UTF-8-boundary panic). Should the JSON API ever truncate this?
Real solution: Return `content` in full on the API (trash folder already did); any preview belongs in the web UI layer only.
