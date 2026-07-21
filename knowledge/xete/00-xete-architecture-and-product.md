# xete — Architecture & Product Overview

A grounded reference on what xete is, how it's built, and the principles behind it. Canonical source of truth for program identity and infra is the 3-file system in `C:\Users\jshed\.hermes\` — `PROJECT_STATE_xete_BY_PROJECT.md` (by project/module), `PROJECT_STATE_xete_BY_TOPIC.md` (by cross-cutting topic), `PROJECT_STATE_xete_INDEX.md` (keyword index) — read `ARCHIVAL_PROTOCOL.md` first (the old single-file `PROJECT_STATE_xete.txt` is retired/read-only history, not live). Never infer program identity from app-code constants — verify against these files and on-chain. This doc is orientation, not a substitute for them. **No secrets/keys belong here — this folder is indexed.**

## 1. What xete is
xete is **infrastructure for provable, confidential communication and settlement between agents** (AI agents and people) — built on Solana. Positioning is **enterprise / sovereign provable data transfer**, not "secure chat": defense, finance, and AI-agent buyers. The core promise is **provable identity + provable value transfer** without a trusted custodial intermediary, so parties can transact without pricing in counterparty/trust risk.

Three pillars:
1. **Identity** — agents are Ed25519 keypairs (Solana-style addresses); human-readable **%aliases** resolve on-chain to agent_id + pubkey.
2. **Messaging** — end-to-end encrypted; the relay sees **ciphertext only**.
3. **Settlement** — on-chain value transfer (payments, swaps, escrow/settlement), non-custodial.

## 2. Design principles (the ethos)
- **Non-custodial** — xete never holds customer funds or fiat. The server never handles money (contract + concierge + watcher do). This is the central regulatory shield (not a money transmitter / VASP) and the anti-run / anti-rug guarantee.
- **Trust-minimized** — untrusted relay, client-side resolution, verify-don't-infer, no master key.
- **Privacy by design** — ciphertext-only relay, metadata minimization (per-message pruning, content nulling at 24h), minimal IP retention (anti-abuse only, never hoarded), pseudonymous identities.
- **Provable + accountable, NOT a mixer** — the framing for all confidential features; confidential *and* provable, deliberately on the right side of the Tornado-Cash/AML line.
- **Right-size rigor to lifespan + blast radius** — nation-state-grade ceremony for durable high-blast-radius surfaces (custody, on-chain programs, the permanent relay); lighter touch for throwaway/temporary features.
- **Test everything before deploy; quality over speed.**

## 3. On-chain programs (Solana) — verify against the state file & on-chain
The program map (from the canonical primer) — **do not confuse these**:
- **Payment detector** — `GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U` — LIVE, upgradeable. (Authority held offline; treat as crown-jewel.)
- **Settlement / escrow-pin** — `GPCsJ6kvrQ61wDG8bpP8315ge7AHfmsUHdxTD7LQ6CoJ` — LIVE, **immutable** (no upgrade key = no upgrade-key risk; the deliberate high-assurance choice for value-bearing code).
- **Swap** — `6mwMBm3FVno89FCEnwqHqzTsQNQdmpz3oubKxpphA9A3` — NOT deployed to mainnet.
- **Alias** — `EgUTCNYKPDTMaKY6bQdP7W7JostBVzQx6L2Yke9aM3Tc` — NOT deployed to mainnet.
(Programs are built **verified/reproducible**, lean, audited — see `../opsec/05-supply-chain-and-hardware-threats.md`.)

## 4. The relay & off-chain infra
- The **relay** is a server that routes E2E-encrypted messages and exposes APIs; it holds **ciphertext + minimal routing metadata only**. Live relay runs as a process behind a Caddy reverse proxy; SQLite-backed. It must never become a content honeypot or a money-handler.
- **Client/relay decoupling** is a standing architectural goal: no client edit should require rebuilding the relay (kill compile-time coupling; serve the PWA frontend at runtime).
- **Fiat on/off-ramp** is delegated to **licensed third parties** — they carry the MSB/KYC/Travel-Rule burden, not xete.

## 5. Clients
- **House Elf (HE)** — desktop (Tauri) vault + messaging; wallet-derived encryption, lock-on-close, native human-presence gates on reveal/export/delete.
- **Saga / Seeker mobile** — Android app (`net.xete.mobile`) using the **Seed Vault** secure element for hardware custody (the seed never leaves the element). Supports hardware *and* software-key wallet import (verified). **Never `adb uninstall`** it (wipes the Seed Vault grant).
- **Concierge** — a richer wallet/app skin (Genesis 16-bit aesthetic), token pages, swap, paint/theming studio, encrypted file vault.
- All clients resolve aliases **client-side from chain** (the source-of-truth decision); the server's alias-resolution code is slated for deletion once all clients are on-chain.

## 6. Crypto stack (see `../cryptography/`)
- **Identity / signing**: Ed25519 (= the Solana address; also the wallet-auth challenge signature).
- **Key exchange**: X25519 ECDH → shared secret.
- **Message payload**: AES-256-GCM (fresh nonce per message), relay sees only ciphertext.
- **Key-lock invariant**: an account's x25519 messaging key can only be **changed by a wallet-auth session**; weaker factors (paired/passkey/device) can only **confirm**, never loosen. Recovery via an authenticated "Repair encryption key" inbox flow.
- **Hardware custody**: Seed Vault / secure element; sign-on-device with confirmation.

## 7. Agents & the local model
xete is itself operated by a small **fleet of agents** (each its own pseudonymous identity/keystore, routed by inbox id, color-tagged) plus an **echo** onboarding bot. John's **local llama3.1 (8B) agent** is grounded as a xete/crypto expert via a **RAG index** (this knowledge library) — retrieval, not fine-tuning; weights untouched. (See `../journal/README.md`, the `rag_*` scripts, and the machine-ops docs.)

## 8. How this all fits
xete is applied cryptography + applied OpSec + applied finance/regulatory awareness, assembled into provable agent-to-agent settlement. Every other doc in this library is, in part, background for *why xete is built the way it is*: the crypto docs (primitives), the law docs (the regulatory perimeter it's designed to stay outside of), the OpSec docs (the threat model it's hardened against), and the finance docs (the value-movement world it operates in). **For anything operational — addresses, infra, deploy state — defer to the canonical state file and on-chain verification, not this overview.**
