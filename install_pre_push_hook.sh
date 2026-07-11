#!/usr/bin/env bash
# Installs the shared pre-push sanity hook into a repo.
# Usage: ./install_pre_push_hook.sh /path/to/repo
set -eu

SANITY_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pre_push_sanity.sh"
REPO="${1:?usage: install_pre_push_hook.sh /path/to/repo}"
HOOKS_DIR="$REPO/.git/hooks"

if [ ! -d "$HOOKS_DIR" ]; then
  echo "no .git/hooks in $REPO — is that a git repo?" >&2
  exit 1
fi

HOOK="$HOOKS_DIR/pre-push"
if [ -e "$HOOK" ] && ! grep -q "pre_push_sanity.sh" "$HOOK" 2>/dev/null; then
  echo "an existing pre-push hook is already at $HOOK and doesn't look like ours — not overwriting." >&2
  echo "back it up and re-run, or merge manually." >&2
  exit 1
fi

cat > "$HOOK" <<EOF
#!/usr/bin/env bash
exec "$SANITY_SCRIPT" "\$@"
EOF
chmod +x "$HOOK"
echo "installed pre-push sanity hook into $HOOK (points at $SANITY_SCRIPT)"
