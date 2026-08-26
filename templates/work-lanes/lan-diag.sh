#!/usr/bin/env bash
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
#   lan-diag.sh GET <url>        http(s) GET, 3s cap, same private-only destination rule
#
# Never: nmap, tcpdump, ssh, sudo, file writes, packet capture, public-internet
# probes, request bodies, redirects. A hostname with ANY public address refuses.

set -euo pipefail

usage() {
  cat <<'EOF'
lan-diag.sh — ShieldCortex lan-diag work lane (read-mostly, private-only)

  lan-diag.sh                 interface + route status (read-only)
  lan-diag.sh status          same
  lan-diag.sh help            this text
  lan-diag.sh <host-or-ip>    ping -c 2 -W 2; loopback / link-local / RFC1918 only
  lan-diag.sh GET <url>       http(s) GET, 3s cap, same private-only destination rule

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
  [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$ ]] || return 1
  addrs="$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)" || return 1
  [[ -n "$addrs" ]] || return 1
  while IFS= read -r addr; do
    is_private_literal "$addr" || return 1
  done <<< "$addrs"
  printf '%s\n' "$addrs" | head -n 1
}

show_status() {
  echo "# interfaces"
  ip -br addr 2>/dev/null || ip addr
  echo
  echo "# routes"
  ip route 2>/dev/null || true
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
  if ! is_private_literal "$host"; then
    # Pin the vetted DNS answer so check-time and connect-time agree.
    [[ "$addr" == *:* ]] && addr="[$addr]"
    resolve_args=(--resolve "${host}:${port}:${addr}")
  fi
  curl --silent --fail --max-time 3 --proto '=http,https' --max-redirs 0 \
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
