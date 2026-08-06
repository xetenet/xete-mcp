#!/bin/bash
# gate-audit.sh — detects weaknesses in the gate system itself from repo history.
# Runs locally or in CI. Prints a markdown report to stdout; exit 0 = clean, exit 2 = findings.
# Usage: scripts/gate-audit.sh [days-back]   (default 90)

DAYS="${1:-90}"
PATTERNS_FILE=".githooks/protected-paths"
FINDINGS=0

echo "# Gate audit — $(date +%Y-%m-%d), last $DAYS days"
echo ""

if [ ! -f "$PATTERNS_FILE" ]; then
  echo "## FINDING: gate not installed"
  echo "No $PATTERNS_FILE — this repo is entirely ungated."
  exit 2
fi

# ---------- Signal 1: ungated protected-path commits on main ----------
echo "## Signal 1: protected-path commits on main without a DDR in the same change"
UNGATED=""
# Never audit earlier than the gate itself existed. Commits made BEFORE the gate was
# installed cannot have bypassed it, and reporting them is a guaranteed false positive:
# on 2026-08-05 this flagged 9 commits dated 2026-05-31..06-15 against a gate installed
# 2026-07-05. Since a finding OPENS A GITHUB ISSUE, that noise lands in the same inbox
# that carries real security mail. An audit that cries wolf about its own pre-history
# trains people to skim it, which is worse than not running it.
GATE_BIRTH=$(git log --diff-filter=A --format=%aI -- "$PATTERNS_FILE" | tail -1)
SINCE_ARG="$DAYS days ago"
if [ -n "$GATE_BIRTH" ]; then
  WINDOW_START=$(date -d "$DAYS days ago" +%s 2>/dev/null || echo 0)
  BIRTH_EPOCH=$(date -d "$GATE_BIRTH" +%s 2>/dev/null || echo 0)
  if [ "$BIRTH_EPOCH" -gt "$WINDOW_START" ] 2>/dev/null; then
    SINCE_ARG="$GATE_BIRTH"
    echo "_Window clamped to the gate's install date ($GATE_BIRTH) — earlier commits predate the gate._"
    echo ""
  fi
fi
for C in $(git log --first-parent --since="$SINCE_ARG" --pretty=%h main 2>/dev/null); do
  FILES=$(git show -m --first-parent --name-only --pretty=format: "$C" | sort -u)
  HIT=""
  while IFS= read -r pattern; do
    case "$pattern" in ""|\#*) continue;; esac
    echo "$FILES" | grep -qE "$pattern" && HIT=1 && break
  done < "$PATTERNS_FILE"
  if [ -n "$HIT" ]; then
    echo "$FILES" | grep -qE '^reviews/DDR-.*\.md$' || UNGATED="$UNGATED $C"
  fi
done
if [ -n "$UNGATED" ]; then
  FINDINGS=1
  echo "**FINDING** — these commits reached main touching protected paths with no DDR change:"
  for C in $UNGATED; do echo "- \`$C\` $(git log -1 --pretty=%s "$C")"; done
  echo "Likely causes: \`--no-verify\` bypass, push before branch protection was enabled, or a protected-paths pattern added after the fact. Verify each; if legitimate gaps, the gate has a hole."
else
  echo "Clean."
fi
echo ""

# ---------- Signal 2: rubber-stamp DDRs (near-duplicate review artifacts) ----------
echo "## Signal 2: near-duplicate DDRs (rubber-stamping)"
DDRS=$(ls -t reviews/DDR-*.md 2>/dev/null | head -10)
DUPES=""
for A in $DDRS; do
  for B in $DDRS; do
    [ "$A" \< "$B" ] || continue
    TOTAL=$(sort -u "$A" "$B" | grep -c '[^[:space:]]')
    COMMON=$(comm -12 <(sort -u "$A") <(sort -u "$B") 2>/dev/null | grep -c '[^[:space:]]')
    [ "$TOTAL" -eq 0 ] && continue
    PCT=$((COMMON * 100 / TOTAL))
    [ "$PCT" -ge 70 ] && DUPES="$DUPES\n- $A vs $B: ${PCT}% identical lines"
  done
done
if [ -n "$DUPES" ]; then
  FINDINGS=1
  echo "**FINDING** — review artifacts are converging on boilerplate:"
  printf '%b\n' "$DUPES"
  echo "Rubber-stamped reviews are worse than no gate (false assurance). Either the reviews are theater — retrain the loop — or these paths shouldn't be protected — trim the patterns."
else
  echo "Clean."
fi
echo ""

# ---------- Signal 3: thin DDRs (no real doubts raised) ----------
echo "## Signal 3: thin DDRs"
THIN=""
for F in $(ls reviews/DDR-*.md 2>/dev/null); do
  LINES=$(grep -c '[^[:space:]]' "$F")
  # Count content inside the "Doubts raised" section. The terminator MUST NOT match the
  # section's own `###` subsections: the original `/^##/` also matched `### D1 ...`, so the
  # counter switched off at the first doubt and reported ZERO for a DDR containing twelve.
  # That made the most thorough review in the repo (DDR-spend-caps, D1-D12, the money path)
  # look like a rubber stamp — an audit bug that discredits good work and hides real ones.
  # `/^## /` matches only same-level headings, since `###` has no space in position 3.
  DOUBTS=$(awk '/^##+ *Doubts raised/{flag=1;next}/^## /{flag=0}flag&&/[^[:space:]]/{n++}END{print n+0}' "$F")
  if [ "$LINES" -lt 15 ] || [ "$DOUBTS" -lt 2 ]; then
    THIN="$THIN\n- $F (${LINES} lines, ${DOUBTS} doubt lines)"
  fi
done
if [ -n "$THIN" ]; then
  FINDINGS=1
  echo "**FINDING** — DDRs with fewer than 2 recorded doubts, meaning no real attack attempts:"
  printf '%b\n' "$THIN"
  echo "A review that raised no doubts didn't try. Require at least one concrete attack attempt per assumption (see doubt-driven-review skill)."
else
  echo "Clean."
fi
echo ""

# ---------- Signal 4: bypass usage and pattern staleness (informational) ----------
echo "## Signal 4: context"
LAST_TUNED=$(git log -1 --pretty=%as -- "$PATTERNS_FILE" 2>/dev/null || echo never)
GATED_COMMITS=$(git log --since="$DAYS days ago" --pretty=%h -- reviews/ 2>/dev/null | wc -l | tr -d ' ')
echo "- protected-paths last tuned: $LAST_TUNED"
echo "- DDR-touching commits in window: $GATED_COMMITS"
if [ "$GATED_COMMITS" = "0" ]; then
  echo "- **Note**: zero gate activity in $DAYS days. Either no contract work happened (fine) or work is routing around the gate (not fine). Human judgment required."
fi

echo ""
if [ "$FINDINGS" -eq 1 ]; then
  echo "---"
  echo "Findings present. Next step: run the gate-retrospective skill against this report and open an improvement PR on xete-agent-skills."
  exit 2
fi
echo "No findings."
exit 0
