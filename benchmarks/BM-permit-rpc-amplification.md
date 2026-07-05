# BM: Unauthenticated RPC-backed read endpoints shipped with no rate limit or cache — hammerable into an RPC-amplification DoS
Source: xete-permit-server culprits 1b065c0, 1c25318 fixed by 65aa46e
Paths: src/server.rs (request router, handle_resolve/handle_quote_*), src/chain.rs (the amplified RPC reads)
Class: validation-gap / resource-exhaustion
Catchable at commit time: yes — the author self-flagged it in the culprit commit message ("add short-TTL cache + per-IP rate limit before public exposure") and an in-code NOTE
Gate mapping: NEW — (a) unauthenticated endpoint calling out to a metered/external resource must land with rate limiting in the same change; (b) no acknowledged-but-deferred security TODO/NOTE may merge on a protected path (known-debt gate)
Doubt prompt: This endpoint is open to anyone and does N on-chain RPC reads per call — what bounds the RPC cost when someone loops it 10k times, and why is that bound not in this diff?
Real solution: Per-IP gate (60/min, keyed off first X-Forwarded-For hop behind the proxy, else peer addr) returning 429 on open reads, plus a 10s TTL cache on resolve results. Residual doubt: the gate trusts client-supplied X-Forwarded-For — spoofable if the server is ever reachable without the proxy.
