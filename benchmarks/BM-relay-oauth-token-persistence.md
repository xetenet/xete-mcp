# BM: X OAuth access/refresh tokens persisted to DB as write-only dead data
Source: xete-relay-clone culprit d5eb9081 fixed by 476076be
Paths: src/x_oauth.rs, src/db.rs
Class: key-leak / secret-at-rest
Catchable at commit time: yes
Gate mapping: secrets/tokens written to persistent storage — is storage necessary, and who can read them on compromise?
Doubt prompt: You store `x_oauth_token`/`x_oauth_secret` on the agent row — is either value ever read again? If not, why persist a per-user OAuth credential that a DB compromise would leak?
Real solution: Stopped writing the tokens (used only transiently in-callback to fetch the username), and added a startup scrub that blanks any legacy stored values.
