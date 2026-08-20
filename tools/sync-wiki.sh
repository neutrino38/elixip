#!/usr/bin/env bash
# Publish the user-facing documentation to the GitHub wiki.
#
#   tools/sync-wiki.sh [--dry-run] [--no-push] [--wiki-dir DIR]
#
# The wiki is a flat namespace: there are no directories and pages reference each
# other by name. So every relative link in the sources has to be resolved against
# the directory of the file that carries it, then mapped through the manifest
# below — `](README.md)` means Kelixip-Modules from docs/kelixip/modules/ but
# Kelixip from docs/kelixip/.
#
# Links pointing outside the manifest (design docs, code, packaging files) become
# absolute URLs into the repository. A link resolving to nothing at all is a dead
# link in the source and aborts the run.
#
# Design docs under docs/design/ are deliberately NOT published.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WIKI_URL="git@github.com:neutrino38/elixip.wiki.git"
BLOB="https://github.com/neutrino38/elixip/blob/master"
TREE="https://github.com/neutrino38/elixip/tree/master"

DRY_RUN=0
PUSH=1
WIKI_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; PUSH=0 ;;
    --no-push)   PUSH=0 ;;
    --wiki-dir)  WIKI_DIR="$2"; shift ;;
    -h|--help)   sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- the manifest
# source (relative to the repo root) | wiki page name | link label, in sidebar
# order. The label replaces the link *text* wherever a source wrote a bare path
# — "[installation.md](installation.md)" reads as "[Installation](…)" on a wiki
# that has no directories. Prose link texts are left alone.
MANIFEST=(
  "README.md|Home|Home"
  "FSL.md|FSL|FSL"
  "BUILD.md|Build|Build"
  "ELIXIPP.md|Elixipp|elixipp"
  "TLS_WSS.md|TLS-and-WSS|TLS and WSS"
  "B2BUA.md|B2BUA|B2BUA"
  "docs/kelixip/README.md|Kelixip|kelixip manual"
  "docs/kelixip/installation.md|Kelixip-Installation|Installation"
  "docs/kelixip/running.md|Kelixip-Running|Running"
  "docs/kelixip/administration.md|Kelixip-Administration|Administration"
  "docs/kelixip/rest-api.md|Kelixip-REST-API|REST API"
  "docs/kelixip/modules/README.md|Kelixip-Modules|Modules"
  "docs/kelixip/modules/registrar.md|Module-Registrar|registrar"
  "docs/kelixip/modules/auth_db.md|Module-Auth-DB|auth_db"
  "docs/kelixip/modules/mcu.md|Module-MCU|mcu"
  "docs/kelixip/modules/mcu-api.md|MCU-API|mcu REST API"
  "docs/kelixip/modules/mcu_module_guide.md|MCU-Guide|mcu operating guide"
  "docs/kelixip/modules/template.md|Module-Template|module template"
  "docs/releases/RELEASE-1.5.1.md|Release-1.5.1|Release 1.5.1"
  "docs/releases/RELEASE-1.5.0.md|Release-1.5.0|Release 1.5.0"
  "docs/releases/RELEASE-1.4.1.md|Release-1.4.1|Release 1.4.1"
  "docs/releases/RELEASE-1.4.0.md|Release-1.4.0|Release 1.4.0"
  "docs/releases/RELEASE-1.2.1.md|Release-1.2.1|Release 1.2.1"
  "docs/releases/RELEASE-1.2.0.md|Release-1.2.0|Release 1.2.0"
  "docs/releases/RELEASE-1.1.0.md|Release-1.1.0|Release 1.1.0"
  "LICENSE.md|License|License"
  "LICENSE_fr.md|License-FR|Licence (français)"
)

# Generated, not copied: Releases.md (index) and _Sidebar.md.

declare -A PAGE_OF LABEL_OF
for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r m_src m_page m_label <<< "$entry"
  PAGE_OF["$m_src"]="$m_page"
  LABEL_OF["$m_page"]="$m_label"
done

# ------------------------------------------------------------------- the wiki
if [ -z "$WIKI_DIR" ]; then
  WIKI_DIR="$REPO/../elixip.wiki"
fi

if ! git ls-remote --exit-code "$WIKI_URL" HEAD >/dev/null 2>&1; then
  cat >&2 <<EOF
==> cannot reach $WIKI_URL

The wiki is pushed over SSH with a passphrase-protected key, so an ssh-agent has
to be running and exported. From an interactive terminal:

    ssh-agent -a /tmp/claude-ssh-agent.sock > /dev/null
    SSH_AUTH_SOCK=/tmp/claude-ssh-agent.sock ssh-add ~/.ssh/id_ed25519

then re-run this script with SSH_AUTH_SOCK=/tmp/claude-ssh-agent.sock exported.
EOF
  exit 1
fi

if [ -d "$WIKI_DIR/.git" ]; then
  echo "==> refreshing $WIKI_DIR"
  git -C "$WIKI_DIR" pull --quiet --ff-only
else
  echo "==> cloning the wiki into $WIKI_DIR"
  git clone --quiet "$WIKI_URL" "$WIKI_DIR"
fi

# ------------------------------------------------------- link rewriting engine
# Resolve one link target, as written in $2, carried by the file $1.
# Echoes the replacement, or exits non-zero when the target does not exist.
resolve_link() {
  local src="$1" target="$2"
  local path="${target%%#*}" anchor=""
  case "$target" in *'#'*) anchor="#${target#*#}" ;; esac

  # A bare "#anchor" is an in-page link: leave it alone.
  [ -z "$path" ] && { printf '%s' "$target"; return 0; }

  local resolved
  case "$path" in
    /*) resolved="${path#/}" ;;
    *)  resolved="$(realpath -m --relative-to="$REPO" "$REPO/$(dirname "$src")/$path")" ;;
  esac

  # Directory links keep their trailing slash through realpath's normalisation.
  local trailing=""
  case "$path" in */) trailing="/" ;; esac

  if [ -n "${PAGE_OF[$resolved]+x}" ]; then
    printf '%s%s' "${PAGE_OF[$resolved]}" "$anchor"
  elif [ -d "$REPO/$resolved" ]; then
    printf '%s/%s%s%s' "$TREE" "$resolved" "$trailing" "$anchor"
  elif [ -e "$REPO/$resolved" ]; then
    printf '%s/%s%s' "$BLOB" "$resolved" "$anchor"
  else
    return 1
  fi
}

# Collect every rewritable target of a file, one per line.
targets_of() {
  grep -o '](\([^)]*\))' "$1" \
    | sed 's/^](//; s/)$//' \
    | grep -v '^http' | grep -v '^mailto:' | grep -v '^#' \
    | sort -u
}

DEAD_LINKS=0

# ------------------------------------------------------------------ the pages
echo "==> ${#MANIFEST[@]} pages"
MAPFILE="$(mktemp)"
trap 'rm -f "$MAPFILE"' EXIT

for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r src page label <<< "$entry"

  [ -f "$REPO/$src" ] || { echo "!! missing source: $src" >&2; exit 1; }

  : > "$MAPFILE"
  n_links=0
  while IFS= read -r target; do
    [ -z "$target" ] && continue
    n_links=$((n_links + 1))
    if replacement="$(resolve_link "$src" "$target")"; then
      # Wiki pages get their manifest label. Links out to the repository get the
      # repo-relative path, so that a "../../design/x.md" written from three
      # directories down still reads as "docs/design/x.md" on a flat wiki.
      case "$replacement" in
        http*) link_label="${replacement#"$BLOB/"}"; link_label="${link_label#"$TREE/"}"
               link_label="${link_label%%#*}" ;;
        *)     link_label="${LABEL_OF[${replacement%%#*}]-}" ;;
      esac
      printf '%s\t%s\t%s\n' "$target" "$replacement" "$link_label" >> "$MAPFILE"
    else
      echo "!! dead link in $src: $target" >&2
      DEAD_LINKS=$((DEAD_LINKS + 1))
    fi
  done < <(targets_of "$REPO/$src")

  printf '    %-42s -> %-24s %2d links\n' "$src" "$page" "$n_links"
  [ "$DRY_RUN" -eq 1 ] && continue

  # Substitute by exact string match, not by regex: the targets contain dots,
  # slashes and hashes that a regex pass would have to escape.
  awk -v mapfile="$MAPFILE" '
    function lastindex(s, c,   i, seen) {
      seen = 0
      for (i = length(s); i > 0; i--)
        if (substr(s, i, 1) == c) { seen = i; break }
      return seen
    }
    # A link text is a path when the author simply pasted the file name, with an
    # optional section suffix: "installation.md", "mcu-api.md §8".
    function pathish(t,   head) {
      head = t
      sub(/ .*$/, "", head)
      return (head ~ /\.md$/ || head ~ /\/$/) && (head == t || t ~ /^[^ ]+ §/)
    }
    BEGIN {
      while ((getline line < mapfile) > 0) {
        n = split(line, kv, "\t")
        repl[kv[1]] = kv[2]
        if (n > 2 && kv[3] != "") label[kv[1]] = kv[3]
      }
    }
    {
      out = ""; rest = $0
      while ((p = index(rest, "](")) > 0) {
        out = out substr(rest, 1, p - 1)
        rest = substr(rest, p + 2)
        q = index(rest, ")")
        if (q == 0) { out = out "]("; continue }
        target = substr(rest, 1, q - 1)
        rest = substr(rest, q + 1)

        # The link text runs from the last unmatched "[" to here.
        b = lastindex(out, "[")
        text = (b > 0) ? substr(out, b + 1) : ""
        if (b > 0 && (target in label) && pathish(text)) {
          suffix = text
          if (sub(/^[^ ]+ /, "", suffix)) suffix = " " suffix; else suffix = ""
          out = substr(out, 1, b) label[target] suffix
        }
        out = out "](" ((target in repl) ? repl[target] : target) ")"
      }
      print out rest
    }
  ' "$REPO/$src" > "$WIKI_DIR/$page.md"
done

if [ "$DEAD_LINKS" -gt 0 ]; then
  echo "==> $DEAD_LINKS dead link(s) in the sources — fix them in the repo first" >&2
  exit 1
fi

# ------------------------------------------------------- the generated pages
if [ "$DRY_RUN" -eq 0 ]; then
  echo "==> Releases.md, _Sidebar.md"

  {
    echo "# Releases"
    echo
    echo "Release notes for each published version, newest first."
    echo
    for entry in "${MANIFEST[@]}"; do
      IFS='|' read -r src page _ <<< "$entry"
      case "$page" in Release-*) ;; *) continue ;; esac
      # The lead paragraph opens with "DATE — N commits since V (DATE). <theme>",
      # wrapped over several lines. Join it, then keep the date and the theme.
      para="$(awk 'NR==1 {next} !seen && !NF {next} NF {seen=1; printf "%s ", $0; next} seen {exit}' "$REPO/$src")"
      date="${para%% *}"
      theme="$(printf '%s' "$para" \
        | sed 's/^[^ ]* — //; s/^[0-9]* commits since [0-9.]* ([0-9-]*)\. *//; s/^Theme of the release: *//' \
        | sed 's/[*_`]//g' \
        | cut -c1-110 | sed 's/ [^ ]*$/…/')"
      echo "- [${page#Release-}]($page) — $date — $theme"
    done
  } > "$WIKI_DIR/Releases.md"

  cat > "$WIKI_DIR/_Sidebar.md" <<'EOF'
### Elixip

- [Home](Home)
- [FSL — the Finite State Language](FSL)
- [Building the artifacts](Build)

**elixipp — the test tool**
- [elixipp guide](Elixipp)
- [TLS and WSS transports](TLS-and-WSS)

**kelixip — the SIP server**
- [Overview](Kelixip)
- [Installation](Kelixip-Installation)
- [Running](Kelixip-Running)
- [Administration](Kelixip-Administration)
- [REST control API](Kelixip-REST-API)

**kelixip modules**
- [Modules overview](Kelixip-Modules)
- [registrar](Module-Registrar)
- [auth_db](Module-Auth-DB)
- [mcu — conferencing](Module-MCU)
- [mcu — REST API](MCU-API)
- [mcu — operating guide](MCU-Guide)
- [Writing a module](Module-Template)

**Call processing**
- [B2BUA](B2BUA)

**Transport**
- [TCP Listener Design](TCP-Listener-Design)

**Releases**
- [All releases](Releases)
- [1.4.1](Release-1.4.1)
- [1.4.0](Release-1.4.0)
- [1.2.1](Release-1.2.1)
- [1.2.0](Release-1.2.0)
- [1.1.0](Release-1.1.0)

**License**
- [License (BSL 1.1)](License)
- [Licence — version française](License-FR)
EOF
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> dry run: nothing written, no dead links"
  exit 0
fi

# ------------------------------------------------------------------ the guard
leftovers="$(grep -rn '](\([^)h#][^)]*\)\?\.md[^)]*)' "$WIKI_DIR"/*.md || true)"
if [ -n "$leftovers" ]; then
  echo "==> relative .md links survived the rewrite:" >&2
  echo "$leftovers" >&2
  exit 1
fi

# ----------------------------------------------------------------- the commit
cd "$WIKI_DIR"
git add -A
if git diff --cached --quiet; then
  echo "==> wiki already up to date"
  exit 0
fi

git diff --cached --stat
git commit --quiet -m "Sync from the repository documentation

Mirrors the user-facing docs: the root guides (FSL, elixipp, build, TLS/WSS,
B2BUA), the kelixip operator manual and its module pages, and the release notes.
Generated by tools/sync-wiki.sh."

if [ "$PUSH" -eq 1 ]; then
  git push --quiet
  echo "==> pushed to $WIKI_URL"
else
  echo "==> committed locally, not pushed (--no-push)"
fi
