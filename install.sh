#!/bin/sh
# voxpbx-tui installer.
#
#   curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh
#
# Options:
#   --prefix <dir>   Install directory (default /usr/local/bin)
#   --version <tag>  Version to install, e.g. v0.1.0 (default: latest)
#   --no-setcap      Do not grant the packet capture capabilities
#   --uninstall      Remove the installed binary
#   -h, --help       Show this help
#
# Environment: VOXPBX_VERSION is equivalent to --version.

set -eu

REPO="savagz/voxpbx-tui"
BIN="voxpbx-tui"
PREFIX="/usr/local/bin"
VERSION="${VOXPBX_VERSION:-}"
UNINSTALL=0
SETCAP=1

info() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    # Inline text: under `curl | sh`, $0 is the shell, not this file.
    cat <<EOF
voxpbx-tui installer.

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh

Options:
  --prefix <dir>   Install directory (default /usr/local/bin)
  --version <tag>  Version to install, e.g. v0.1.0 (default: latest)
  --no-setcap      Do not grant the packet capture capabilities
  --uninstall      Remove the installed binary
  -h, --help       Show this help

Environment: VOXPBX_VERSION is equivalent to --version.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || die "--prefix requires a directory"
            PREFIX="$2"; shift 2 ;;
        --version)
            [ $# -ge 2 ] || die "--version requires a tag"
            VERSION="$2"; shift 2 ;;
        --no-setcap) SETCAP=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# Run with sudo only if the destination is not writable.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "write permission on $PREFIX is required (use --prefix or install sudo)"
    fi
}

install_file() {
    # $1 source, $2 destination
    dest_dir=$(dirname "$2")
    # Try to create the directory without root first (e.g. ~/.local/bin).
    mkdir -p "$dest_dir" 2>/dev/null || true
    if [ -d "$dest_dir" ] && [ -w "$dest_dir" ]; then
        install -m 0755 "$1" "$2"
    else
        as_root mkdir -p "$dest_dir"
        as_root install -m 0755 "$1" "$2"
    fi
}

if [ "$UNINSTALL" -eq 1 ]; then
    target="$PREFIX/$BIN"
    [ -e "$target" ] || die "$target does not exist"
    if [ -w "$PREFIX" ]; then rm -f "$target"; else as_root rm -f "$target"; fi
    info "Removed $target"
    exit 0
fi

[ "$(uname -s)" = "Linux" ] || die "only Linux is supported (detected: $(uname -s))"
[ "$(uname -m)" = "x86_64" ] || die "only x86_64 is supported (detected: $(uname -m))"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    # Final URL after following redirects.
    resolve_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
    resolve_url() {
        # wget prints "Location: <url> [following]"; keep only the URL.
        wget -S --spider "$1" 2>&1 | tr -d '\r' \
            | sed -n 's/^[[:space:]]*Location:[[:space:]]*\([^[:space:]]*\).*/\1/p' | tail -n 1
    }
else
    die "curl or wget is required"
fi
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

if [ -z "$VERSION" ]; then
    info "Looking up the latest release..."
    # github.com/<repo>/releases/latest redirects to .../releases/tag/<tag>;
    # unlike the API it is not rate limited.
    latest=$(resolve_url "https://github.com/$REPO/releases/latest") \
        || die "could not query the latest release"
    case "$latest" in
        */releases/tag/?*) VERSION=${latest##*/} ;;
        *) die "could not determine the latest release" ;;
    esac
fi

# Accept "1.2.3" as well as "v1.2.3".
case "$VERSION" in
    v*) ;;
    *) VERSION="v$VERSION" ;;
esac

name="$BIN-$VERSION-x86_64-linux"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

info "Downloading $name.tar.gz..."
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || die "could not download $base/$name.tar.gz"
fetch "$base/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256" || die "could not download the checksum"

info "Verifying checksum..."
(cd "$tmp" && sha256sum -c "$name.tar.gz.sha256" >/dev/null) || die "checksum mismatch, aborting"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
[ -f "$tmp/$name/$BIN" ] || die "the package does not contain $BIN"

install_file "$tmp/$name/$BIN" "$PREFIX/$BIN"

info "Installed to $PREFIX/$BIN"
"$PREFIX/$BIN" --version || true

# The SIP trace opens the interface in capture mode. A capability on the
# binary avoids running the whole TUI as root.
caps="cap_net_raw,cap_net_admin+eip"
if [ "$SETCAP" -eq 1 ]; then
    if ! command -v setcap >/dev/null 2>&1; then
        info "Warning: setcap not found (package libcap2-bin or libcap); the SIP trace needs:"
        info "  sudo setcap $caps $PREFIX/$BIN"
    elif { [ "$(id -u)" -eq 0 ] && setcap "$caps" "$PREFIX/$BIN"; } \
        || { [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 \
             && sudo setcap "$caps" "$PREFIX/$BIN"; }; then
        info "Granted $caps for packet capture."
    else
        info "Warning: could not grant the capture capabilities; the SIP trace needs:"
        info "  sudo setcap $caps $PREFIX/$BIN"
    fi
fi

info "The first run opens the setup wizard, which asks for the AMI credentials and checks packet capture."
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) info "Warning: $PREFIX is not in your PATH." ;;
esac
