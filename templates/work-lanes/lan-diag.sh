#!/bin/bash -p
#
# ShieldCortex work-lane template — lan-diag v1 (#401)
#
# Read-mostly LAN diagnostics with a bounded, private-only reachability check.
# Shipping this file inside the shieldcortex npm package does NOT approve it:
# Action Guard only honours a pin the operator added themselves.
#
# Install (operator, from a real terminal on the host):
#   mkdir -p ~/.shieldcortex/work-lanes
#   cp templates/work-lanes/lan-diag.sh ~/.shieldcortex/work-lanes/lan-diag.sh
#   chmod 0755 ~/.shieldcortex/work-lanes/lan-diag.sh
#   shieldcortex allowlist add ~/.shieldcortex/work-lanes/lan-diag.sh
#
# Scope — anything not listed below refuses (fail closed):
#   lan-diag.sh                  interface + route status (read-only)
#   lan-diag.sh status           same
#   lan-diag.sh help             usage
#   lan-diag.sh <host-or-ip>     ping -c 2 -W 2 — loopback / link-local / RFC1918 only
#   lan-diag.sh GET <url>        http(s) GET, 3s cap, private-only; link-local/IMDS refused
#
# Never: nmap, tcpdump, ssh, sudo, file writes, packet capture, public-internet
# probes, request bodies, redirects. A hostname with ANY public address refuses.

# SOL review hardening (round 2): a pinned hash does not pin the interpreter
# or its startup environment.
#  - The shebang runs bash in privileged mode (-p): BASH_ENV/ENV are NOT
#    processed and functions imported from the environment are ignored, so a
#    hostile startup payload cannot run before this line.
#  - PATH/proxy/locale scrub is verified, not sentinel-trusted: a caller who
#    fakes the sentinel but keeps a hostile environment still fails the check
#    below and gets re-exec'd into the scrubbed state. Termination is
#    guaranteed because the re-exec constructs exactly the state the check
#    requires.
LAN_DIAG_PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [[ "${PATH:-}" != "$LAN_DIAG_PATH" || -n "${BASH_ENV:-}" || -n "${ENV:-}" \
      || -n "${http_proxy:-}${https_proxy:-}${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}${all_proxy:-}${NO_PROXY:-}${no_proxy:-}${CURL_HOME:-}${XDG_CONFIG_HOME:-}" ]]; then
  exec /usr/bin/env -i \
    PATH="$LAN_DIAG_PATH" \
    HOME="${HOME:-/root}" \
    LANG=C LC_ALL=C \
    /bin/bash -p "$0" "$@"
fi

set -euo pipefail

usage() {
  cat <<'EOF'
lan-diag.sh — ShieldCortex lan-diag work lane (read-mostly, private-only)

  lan-diag.sh                 interface + route status (read-only)
  lan-diag.sh status          same
  lan-diag.sh help            this text
  lan-diag.sh <host-or-ip>    ping -c 2 -W 2; loopback / link-local / RFC1918 only
  lan-diag.sh GET <url>       http(s) GET, 3s cap, private-only; link-local/IMDS refused

Refuses everything else: public or global-IPv6 destinations, hostnames with any
public address, redirects, request bodies, scans, captures.
EOF
}

refuse() {
  echo "lan-diag: refused — $*" >&2
  exit 2
}

is_private_ipv4() {
  local ip="$1" a b c d o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
  for o in "$a" "$b" "$c" "$d"; do
    # Reject leading-zero octets outright: "010.0.0.1" is decimal 10 here but
    # octal 8 to many network stacks — ambiguous literals are refused, not
    # normalised (SOL review).
    [[ "$o" =~ ^0[0-9]+$ ]] && return 1
    (( 10#$o <= 255 )) || return 1
  done
  a=$((10#$a)) b=$((10#$b))
  (( a == 127 )) && return 0                     # loopback
  (( a == 10 )) && return 0                      # RFC1918
  (( a == 172 && b >= 16 && b <= 31 )) && return 0
  (( a == 192 && b == 168 )) && return 0
  (( a == 169 && b == 254 )) && return 0         # link-local
  return 1
}

is_private_ipv6() {
  local ip
  ip="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$ip" == "::1" ]] && return 0               # loopback
  case "$ip" in                                  # link-local fe80::/10
    fe8?:*|fe9?:*|fea?:*|feb?:*) return 0 ;;
  esac
  return 1                                       # global + ULA + everything else
}

is_private_literal() {
  is_private_ipv4 "$1" || is_private_ipv6 "$1"
}

# Print one vetted address for "$1". A literal passes on its own range; a
# hostname must resolve to at least one address with EVERY address private.
resolve_private() {
  local host="$1" addrs addr
  if is_private_literal "$host"; then
    printf '%s\n' "$host"
    return 0
  fi
  # inet_aton-style numeric literals ("0177.0.0.1", "2130706433", "0x7f.0.0.1")
  # must not fall through to getent where the OS canonicalises them. A token
  # whose every dot-label is decimal/octal/hex-numeric is an ADDRESS LITERAL:
  # it already failed the strict dotted-quad decimal parser — refuse it
  # (SOL review round 2).
  local __label __all_numeric=1
  IFS='.' read -ra __labels <<< "$host"
  for __label in "${__labels[@]}"; do
    [[ "$__label" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || { __all_numeric=0; break; }
  done
  (( __all_numeric )) && return 1
  [[ "$host" == *:* ]] && return 1
  [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$ ]] || return 1
  [[ "$host" =~ [A-Za-z] ]] || return 1
  addrs="$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)" || return 1
  [[ -n "$addrs" ]] || return 1
  while IFS= read -r addr; do
    is_private_literal "$addr" || return 1
  done <<< "$addrs"
  printf '%s\n' "$addrs" | head -n 1
}

show_status() {
  echo "# interfaces"
  if command -v ip >/dev/null 2>&1; then
    ip -br addr 2>/dev/null || ip addr
  else
    ifconfig 2>/dev/null || true               # macOS / BSD hosts have no iproute2
  fi
  echo
  echo "# routes"
  if command -v ip >/dev/null 2>&1; then
    ip route 2>/dev/null || true
  else
    netstat -rn 2>/dev/null || true
  fi
}

do_ping() {
  local dest="$1" host="$1" zone="" addr
  if [[ "$host" == *%* ]]; then                  # fe80::1%eth0 — zone on the literal only
    zone="%${host#*%}"
    host="${host%%\%*}"
    is_private_ipv6 "$host" || refuse "zone ids are only accepted on link-local IPv6 literals"
  fi
  addr="$(resolve_private "$host")" \
    || refuse "'$dest' is not loopback, link-local, or RFC1918 (or resolves to a public address)"
  if [[ "$addr" == *:* ]]; then
    ping -6 -c 2 -W 2 "${addr}${zone}"
  else
    ping -c 2 -W 2 "$addr"
  fi
}

# GET-path destination rule is stricter than ping: link-local (169.254/16,
# fe80::/10) is REFUSED because an allowlisted HTTP client to link-local is an
# IMDS credential grab (169.254.169.254, [fd00:ec2::254], [fe80::a9fe:a9fe])
# with a TTY pin on it (Grok review). Ping keeps link-local for LAN diagnosis.
is_get_dest_allowed() {
  local ip="$1" a b
  if [[ "$ip" == *:* ]]; then
    # IPv6: loopback only for GET. fe80::/10 refused (IMDS aliases live there);
    # ULA/global were never allowed.
    [[ "$(printf '%s' "$ip" | tr '[:upper:]' '[:lower:]')" == "::1" ]]
    return
  fi
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\. ]] || return 1
  a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
  (( a == 169 && b == 254 )) && return 1         # IMDS / link-local refused on GET
  return 0
}

do_get() {
  local url="$1" rest hostport host port="" addr resolve_args=()
  case "$url" in
    http://*)  rest="${url#http://}"  port=80 ;;
    https://*) rest="${url#https://}" port=443 ;;
    *) refuse "GET accepts http:// or https:// URLs only" ;;
  esac
  hostport="${rest%%/*}"
  [[ "$hostport" == *@* ]] && refuse "userinfo in URLs is not accepted"
  if [[ "$hostport" == \[* ]]; then              # [::1]:8080
    host="${hostport%%]*}"
    host="${host#[}"
    local after="${hostport#*]}"
    [[ "$after" == :* ]] && port="${after#:}"
  elif [[ "$hostport" == *:* ]]; then
    host="${hostport%%:*}"
    port="${hostport##*:}"
  else
    host="$hostport"
  fi
  [[ -n "$host" ]] || refuse "URL has no host"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( port >= 1 && port <= 65535 )) || refuse "bad port '$port'"
  addr="$(resolve_private "$host")" \
    || refuse "'$host' is not loopback, link-local, or RFC1918 (or resolves to a public address)"
  is_get_dest_allowed "$addr" \
    || refuse "GET to link-local/IMDS ranges (169.254/16, fe80::/10) is not allowed — use the ping form for reachability"
  if ! is_private_literal "$host"; then
    # Pin the vetted DNS answer so check-time and connect-time agree.
    [[ "$addr" == *:* ]] && addr="[$addr]"
    resolve_args=(--resolve "${host}:${port}:${addr}")
  fi
  # -q ignores ~/.curlrc; --noproxy '*' + scrubbed env stop proxy routing;
  # --disable is the long form of -q kept explicit for readability on review.
  curl -q --noproxy '*' --silent --fail --max-time 3 --proto '=http,https' --max-redirs 0 \
    "${resolve_args[@]}" \
    --output /dev/null --write-out "GET ${url} -> HTTP %{http_code} (%{time_total}s)\n" \
    "$url"
}

main() {
  local cmd="${1:-status}"
  case "$cmd" in
    status)
      [[ $# -le 1 ]] || refuse "status takes no arguments"
      show_status
      ;;
    help|-h|--help)
      usage
      ;;
    GET|get)
      [[ $# -eq 2 ]] || refuse "usage: lan-diag.sh GET <url>"
      do_get "$2"
      ;;
    -*)
      refuse "unknown option '$cmd'"
      ;;
    *)
      [[ $# -eq 1 ]] || refuse "the ping form takes exactly one destination"
      do_ping "$cmd"
      ;;
  esac
}

main "$@"
