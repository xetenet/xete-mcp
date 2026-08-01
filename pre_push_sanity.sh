#!/usr/bin/env bash
# git pre-push hook body. Installed via install_pre_push_hook.sh into any repo's
# .git/hooks/pre-push, which just execs this file so every installed repo shares
# one implementation.
#
# Reads the standard pre-push stdin protocol:
#   <local ref> <local sha1> <remote ref> <remote sha1>
# For each updated ref, blocks a force-push that would orphan real commits
# (the OWL incident: a force-push silently dropped work with no warning).
# Override for a deliberate force-push: ALLOW_FORCE_PUSH=1 git push ...
#
# Also prints a non-blocking heads-up on unusually large deletions in an
# otherwise-normal fast-forward push, in case it's an accidental mass-delete.

set -u
ZERO="0000000000000000000000000000000000000000"
blocked=0

while read -r local_ref local_sha remote_ref remote_sha; do
  [ -z "${local_ref:-}" ] && continue

  if [ "$local_sha" = "$ZERO" ]; then
    echo "[pre-push] deleting $remote_ref on remote — not blocked, just noting it."
    continue
  fi

  if [ "$remote_sha" = "$ZERO" ]; then
    n=$(git rev-list --count "$local_sha" 2>/dev/null)
    echo "[pre-push] $local_ref: new remote ref, pushing $n commit(s). OK."
    continue
  fi

  if git merge-base --is-ancestor "$remote_sha" "$local_sha" 2>/dev/null; then
    stat=$(git diff --shortstat "$remote_sha" "$local_sha" 2>/dev/null)
    del=$(echo "$stat" | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+' || echo 0)
    ins=$(echo "$stat" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
    if [ "${del:-0}" -gt 500 ] && [ "${del:-0}" -gt $(( ${ins:-0} * 5 + 50 )) ]; then
      echo "[pre-push] WARNING: $local_ref is a fast-forward but deletes ${del} lines vs ${ins} insertions."
      echo "           Not blocking — just make sure this mass-deletion is intentional."
    fi
    continue
  fi

  # Non-fast-forward: figure out what would be orphaned by this force-push.
  orphaned=$(git rev-list "$local_sha..$remote_sha" 2>/dev/null)
  if [ -z "$orphaned" ]; then
    echo "[pre-push] $local_ref: non-fast-forward, but no commits would be orphaned. Proceeding."
    continue
  fi

  count=$(echo "$orphaned" | wc -l)
  echo "=================================================================="
  echo "[pre-push] BLOCKING FORCE-PUSH on $local_ref"
  echo "  This push is NOT a fast-forward. It would orphan $count commit(s)"
  echo "  currently reachable on the remote but not in your local history:"
  echo ""
  git log --no-walk --format='    %h  %ad  %an  %s' --date=short $orphaned
  echo ""
  if [ "${ALLOW_FORCE_PUSH:-}" = "1" ]; then
    echo "  ALLOW_FORCE_PUSH=1 is set — proceeding anyway. This is a deliberate override."
    echo "=================================================================="
  else
    echo "  If this is deliberate, re-run with: ALLOW_FORCE_PUSH=1 git push ..."
    echo "  If it's not, stop and go find out where that history went first."
    echo "=================================================================="
    blocked=1
  fi
done

exit $blocked
