---
name: solana-security-hardening
description: Security checklist and audit persona for Solana/Rust smart contract code, cryptographic client code, AND server-side surfaces (relay, permit server, MCP). MUST be used when writing or modifying any instruction handler, account validation, CPI call, PDA derivation, arithmetic on token amounts, key handling in Black Knight, encryption in Xete Message / the MCP server, HTTP handlers/routes, secret persistence, or schema migrations. Also trigger on "audit", "security review", "harden", or before any mainnet deployment.
---

# Solana Security Hardening

Run this checklist against every diff in scope. Each item is a gate: pass, or document why it does not apply. "Probably fine" fails the gate. Items tagged `(BM-…)` were added because this codebase shipped that exact bug once — the benchmark file holds the doubt prompt.

## On-chain (xete-tab / Xete Swap)

### Account validation
- [ ] Every account's owner is checked against the expected program
- [ ] Every signer requirement is enforced (`is_signer`), including on close/settle paths
- [ ] PDA derivations re-verified in the program, never trusted from client-supplied bump/address
- [ ] Account discriminators / type checks prevent substituting one account type for another
- [ ] Writable accounts justified — no account writable that doesn't need to be
- [ ] CPI account-list completeness across asset variants: for every external-program CPI, the callee's optional/conditional accounts are enumerated and each input variant (standalone vs collection-member, Token vs Token-2022, …) is either supported or explicitly rejected, with a test per variant (BM-swap-core-cpi-collection)

### Arithmetic
- [ ] All token/lamport math uses checked ops (`checked_add`, `checked_sub`, `checked_mul`) or saturating with explicit rationale
- [ ] `overflow-checks = true` in release profile confirmed in Cargo.toml
- [ ] Rounding direction on any division is explicit and favors the protocol/counterparty as intended

### State & flow
- [ ] Commitment scheme preimages include all fields that must not be malleable (SHA256 inputs enumerated in a comment)
- [ ] No instruction can be replayed to double-settle a tab; replay protection identified by name
- [ ] Close/settle paths zero or reassign lamports correctly (no resurrection attacks)
- [ ] Any state referenced by address is re-validated against the agreed terms at settle time — a closed PDA can be recreated at the same address with different contents; takers/acceptors supply expected-terms (slippage) bounds (BM-swap-pda-reopen-rug)
- [ ] Degenerate economics rejected at creation time: zero amounts, born-expired timestamps (BM-swap-zero-amount-listings)
- [ ] Every value transfer moves a priced/consented amount the caller agreed to — never a balance read (BM-relay-payment-drainer)
- [ ] CPI targets validated by program ID, not by account position

## Client-side crypto (Xete Message, MCP server, Black Knight)

- [ ] Nonces for AES-256-GCM are never reused per key: generation strategy stated (random 96-bit or counter) and enforced in code
- [ ] x25519 shared secrets run through a KDF before use as AES keys; raw DH output never used directly
- [ ] Private keys never leave the signing boundary: no logging, no serialization into messages, no error strings containing key material
- [ ] Black Knight policy checks happen BEFORE signing, in the same process as the key, not advisory in the UI layer
- [ ] Constant-time comparison for any MAC/tag/secret equality check
- [ ] Ephemeral pairing keys (iOS PWA bootstrap) are single-use and destroyed after pairing; destruction verified in code, not assumed
- [ ] No hand-rolled implementation of a protocol/crypto primitive (PDA derivation, on-curve checks, KDFs) where a library implementation exists; any "rough heuristic" / "in production use the real check" comment is an automatic OPEN-GATE (BM-relay-fake-pda-derivation)

## Server-side surface (relay, permit server, MCP)

- [ ] Every new HTTP handler is authenticated and scoped to the caller's own data (BM-relay-data-usage-unauth)
- [ ] Any unauthenticated endpoint that touches a metered/external resource (RPC, mail, SMS) lands with rate limiting and/or caching in the same change — not a follow-up (BM-permit-rpc-amplification)
- [ ] No acknowledged-but-deferred security TODO/NOTE merges on a protected path; deferral requires human sign-off recorded in the DDR (BM-permit-rpc-amplification)
- [ ] No security check is a no-op: an empty body or a discarded return value fails this gate — verify enforcement, not existence (BM-relay-blocklist-noop)
- [ ] No route is registered to a stub/`not_implemented` handler on a value-moving or auth-relevant surface (BM-relay-wager-stub-routes)
- [ ] Secrets/tokens written to persistent storage: necessity justified, the read path identified, and the compromise blast radius stated; write-only secrets are removed (BM-relay-oauth-token-persistence)
- [ ] Schema migrations reference only columns that exist on the *old* production schema at each step; tested against a copy of prod data (BM-relay-migration-ordering)
- [ ] Opaque ciphertext fields are never truncated or transformed outside the UI layer (BM-relay-ciphertext-truncation)

## Dependencies
- [ ] `cargo audit` / `pip-audit` clean, or exceptions documented with issue links
- [ ] No new dependency added for functionality under ~100 lines of writable code

## Output

Append results to the active `reviews/DDR-*.md` under a `## Security gates` heading, listing each failed-then-fixed gate and each documented N/A. The doubt-driven-review verdict cannot be SHIP with open gates.
