#!/usr/bin/env bash
# Build a throwaway fixture: a fake "upstream" repo and a "fork" of it.
#
# Usage: build_fixture.sh <dest-dir> <scenario>
#   scenarios:
#     clean    - 2 custom commits on fork's old release, no conflicts on new release
#     conflict - 1 of the custom commits touches a line upstream also changed
#
# After it runs, you'll have:
#   <dest-dir>/upstream/   bare-ish source repo with release/v1.0.0 and release/v1.1.0
#   <dest-dir>/fork/       clone with `origin` and `upstream` remotes; checked out on release/v1.0.0 with custom commits

set -euo pipefail

DEST="${1:?usage: build_fixture.sh <dest-dir> <scenario>}"
SCENARIO="${2:?usage: build_fixture.sh <dest-dir> <scenario>}"

if [[ -e "$DEST" ]]; then
  echo "refusing to overwrite existing $DEST" >&2
  exit 1
fi

mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"

# --- Build upstream -----------------------------------------------------------
UPSTREAM="$DEST/upstream"
git init --quiet --initial-branch=main "$UPSTREAM"
cd "$UPSTREAM"
git config user.email "upstream@example.com"
git config user.name  "Upstream Maintainer"

cat > server.go <<'EOF'
package main

func Listen() string {
    return "tcp://0.0.0.0:4222"
}
EOF
cat > README.md <<'EOF'
# fake-nats
EOF

git add . && git commit --quiet -m "initial commit"

# v1.0.0 release branch + tag
git checkout --quiet -b release/v1.0.0
echo "// release v1.0.0" >> server.go
git commit --quiet -am "Release v1.0.0"
git tag v1.0.0

# v1.1.0 release branch + tag, branching from main
git checkout --quiet main
git checkout --quiet -b release/v1.1.0
case "$SCENARIO" in
  clean)
    cat >> server.go <<'EOF'

func Version() string {
    return "1.1.0"
}
EOF
    ;;
  conflict)
    # upstream replaces the Listen() body — will conflict with the fork's custom edit
    cat > server.go <<'EOF'
package main

func Listen() string {
    return "tcp://[::]:4222"
}

func Version() string {
    return "1.1.0"
}
EOF
    ;;
  *)
    echo "unknown scenario: $SCENARIO" >&2
    exit 1
    ;;
esac
git commit --quiet -am "Release v1.1.0"
git tag v1.1.0

git checkout --quiet main

# --- Build fork ---------------------------------------------------------------
FORK="$DEST/fork"
git clone --quiet "$UPSTREAM" "$FORK"
cd "$FORK"
git config user.email "forker@example.com"
git config user.name  "Forker"
git remote rename origin upstream-tmp
git remote add origin "$UPSTREAM"-mirror
# We need an `origin` that's a separate repo so pushes don't pollute upstream.
git clone --quiet --bare "$UPSTREAM" "$UPSTREAM-mirror"
git remote set-url origin "$UPSTREAM-mirror"
git remote rename upstream-tmp upstream
git fetch --quiet origin
git fetch --quiet upstream

# Apply custom commits to release/v1.0.0
git checkout --quiet -b release/v1.0.0 upstream/release/v1.0.0

cat > custom_dialer.go <<'EOF'
package main

// CustomDialer is a fork-only addition.
func CustomDialer() string {
    return "dialer-v1"
}
EOF
git add custom_dialer.go
git commit --quiet -m "add custom dialer"

# Second custom commit — a minimal in-place edit of Listen()'s return.
# In the "conflict" scenario, upstream also edits this line, so cherry-pick will conflict.
# In the "clean" scenario, upstream doesn't touch this line, so it applies cleanly.
sed -i 's|"tcp://0.0.0.0:4222"|"tcp://0.0.0.0:4222 (custom)"|' server.go
git commit --quiet -am "tweak Listen() output"

git push --quiet -u origin release/v1.0.0
git tag v1.0.0-fork
git push --quiet origin v1.0.0-fork

cd "$DEST"
cat <<EOF
Fixture built at: $DEST
  fork repo:     $FORK
  upstream repo: $UPSTREAM
  origin mirror: $UPSTREAM-mirror
  scenario:      $SCENARIO

Custom commits on release/v1.0.0:
$(cd "$FORK" && git log --oneline upstream/release/v1.0.0..release/v1.0.0)

Available upstream releases: v1.0.0, v1.1.0
EOF
