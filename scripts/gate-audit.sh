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
for C in $(git log --first-parent --since="$DAYS days ago" --pretty=%h main 2>/dev/null); do
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
  DOUBTS=$(awk '/^##+ *Doubts raised/{flag=1;next}/^##/{flag=0}flag&&/[^[:space:]]/{n++}END{print n+0}' "$F")
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
