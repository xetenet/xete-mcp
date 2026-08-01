# xete-mcp — next versions

Deferred ideas for the published MCP package. Nothing here is committed work; it is the
list of things we decided were real but not now, with enough context to pick up cold.

---

## Update checker

**Raised:** 2026-08-01, by John, during the 0.1.5 version decision.
**Status:** open — deliberately deferred, "issue for arguing another day."

**The idea:** the package should be able to tell the operator that a newer version exists.

**Why it came up:** we chose to stay in the `0.1.x` range rather than bump to `0.2.0`, on
the grounds that the project is still in its infancy. The cost of that choice is that the
version number no longer carries a signal — a release with a keystore migration in it looks,
from the version string alone, exactly like a bugfix. A version number is a weak channel for
"you should read the release note before upgrading." An update checker is the strong one.

**What has to be argued before building it:**

- **It is a network call the user did not ask for.** This package's entire pitch is that the
  server only ever sees ciphertext. A phone-home on startup — even to PyPI, even anonymous —
  is a new outbound connection from a privacy tool, and it leaks "this agent is running right
  now" plus a rough version fingerprint to whoever serves it. That is a real objection, not a
  formality.
- **Where it runs.** On MCP server startup is the obvious place and the worst one: it adds
  latency and a failure mode to every agent boot. A dedicated `xete_check_for_updates` tool
  that the agent calls when it wants to is opt-in by construction and costs nothing when unused.
- **What it checks against.** PyPI's JSON API is the low-effort answer. `server.json` in the
  MCP registry is the more correct one for MCP consumers, and we publish both, so they can
  disagree — which is itself worth surfacing.
- **What it does with the answer.** Reporting is safe. Self-updating is not, and should be
  out of scope: this package holds the keystore.

**The one thing it should carry if built:** whether the newer version needs a migration.
`server.json` has no field for that today. Inventing one is part of the work.

---

## (not xete-mcp, parked here so it is not lost) xete-site: /login and /get-started are undeployed

**Found:** 2026-08-01, chasing hourly GitHub failure mail.
**Status:** FIXED and verified 2026-08-01 17:12 UTC. `verify.yml` run 30709817620 green,
`ok /get-started` / `ok /login`. Kept here as the record of what it was.

`verify-site-integrity` has failed every ~15 min since at least 2026-07-20 on two routes,
`/get-started` and `/login` (one shared page). The live site is running an OLD build:

    repo:  <script src="/js/nacl-1.0.3.min.js" integrity="sha384-LMUiUHpaYNGZFzWFRjs...">
    live:  <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl.min.js">

That is the whole diff (24527 vs 24478 bytes). The repo already holds the fix — vendored
locally with a subresource-integrity hash — and it was never copied to the webroot.

Why it is not merely cosmetic: this is the login page, where keys are handled, and the live
version pulls its crypto from a third party with NO integrity check, so a jsdelivr
compromise or any MITM on that request substitutes the crypto library silently. The site's
CSP names `https://cdn.jsdelivr.net` explicitly and is `Report-Only`, so it neither blocks
nor reports this.

Second-order damage, arguably worse: an integrity alarm that has cried wolf hourly for
eleven days is an alarm nobody reads. The next real tamper alert lands in a mailbox already
trained to ignore it.

Fix is a webroot file copy on the production box, no rebuild and no service restart.

**What it actually was, once opened:** not a stale page — a missing file. The vendored
`nacl.min.js` was on disk with a sha384 matching the page's SRI exactly; the page asked for
`/js/nacl-1.0.3.min.js`, which was 404. Deploying the repo page alone would have shipped a
login page whose crypto library did not load at all. Fix was the page plus the versioned
filename (the unversioned name is kept — `setup.html` and `pwa-install.html` reference it).
Backup: `/root/webroot-backups/xete-login.html.20260801-171156`.
