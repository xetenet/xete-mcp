# BM: Public /wager/* escrow routes registered as unauthenticated not_implemented stubs
Source: xete-relay-clone culprits 13a1e6c8, 73fc497e fixed by 69b5a848
Paths: src/main.rs, src/admin/mod.rs, src/admin/escrow_relay.rs
Class: auth / attack-surface exposure
Catchable at commit time: yes
Gate mapping: newly registered route to a stub/not_implemented handler — is a value/escrow endpoint being exposed before auth + settlement exist?
Doubt prompt: These `/wager/propose|accept|cancel|evaluate` routes are wired to handlers that are `not_implemented` stubs — should value-moving escrow endpoints be publicly reachable before auth and on-chain settlement are built?
Real solution: Unregistered all `/wager/*` routes (now 404), kept handlers under `#[allow(dead_code)]` until the feature ships with auth + on-chain settlement.
