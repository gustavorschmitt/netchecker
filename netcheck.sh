#!/usr/bin/env bash
# netcheck.sh — Network quality and TCP diagnostics (with dependency check & interactive install)
# Usage:
#   sudo bash netcheck.sh [-u https://example.com] [-p 8.8.8.8] [-s IPERF_SERVER] [-d 20] [--udp] [--tcpdump 30]
# Examples:
#   bash netcheck.sh
#   bash netcheck.sh -u https://google.com -p 1.1.1.1 -s 203.0.113.10 -d 30
#   sudo bash netcheck.sh -s 203.0.113.10 --udp
#
# Notes:
# - iperf3 requires an iperf3 server you control (start with: `iperf3 -s`)
# - mtr may require sudo to see ICMP properly on some distros
# - tcpdump capture is optional and requires sudo
# - This script can check and install missing dependencies (asks for confirmation)

set -euo pipefail

URL="https://google.com"
PING_TARGET="8.8.8.8"
IPERF_SERVER=""
DURATION=20
DO_UDP=false
TCPDUMP_SECS=0

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) URL="$2"; shift 2;;
    -p|--ping) PING_TARGET="$2"; shift 2;;
    -s|--iperf-server) IPERF_SERVER="$2"; shift 2;;
    -d|--duration) DURATION="$2"; shift 2;;
    --udp) DO_UDP=true; shift;;
    --tcpdump) TCPDUMP_SECS="${2:-0}"; shift 2;;
    -h|--help)
      sed -n '1,80p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

timestamp() { date +"%Y-%m-%d_%H-%M-%S"; }
TS="$(timestamp)"
OUTDIR="netcheck_${TS}"
mkdir -p "$OUTDIR"

# ---------- Dependency detection & installer ----------
# Detect distro and package manager
PKG_MGR=""
INSTALL_CMD=""
SUDO=""
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO=""
  fi
fi

source /etc/os-release 2>/dev/null || true
ID_LOWER="${ID:-}"
ID_LIKE_LOWER="${ID_LIKE:-}"

if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
  INSTALL_CMD="$SUDO apt-get update && $SUDO apt-get install -y"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
  INSTALL_CMD="$SUDO dnf install -y"
elif command -v yum >/dev/null 2>&1; then
  PKG_MGR="yum"
  INSTALL_CMD="$SUDO yum install -y"
elif command -v zypper >/dev/null 2>&1; then
  PKG_MGR="zypper"
  INSTALL_CMD="$SUDO zypper install -y"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MGR="pacman"
  INSTALL_CMD="$SUDO pacman -S --noconfirm"
elif command -v apk >/dev/null 2>&1; then
  PKG_MGR="apk"
  INSTALL_CMD="$SUDO apk add --no-cache"
fi

# Map binaries to package names by family
pkg_for_bin() {
  local bin="$1"
  case "$PKG_MGR" in
    apt)
      case "$bin" in
        dig) echo "dnsutils" ;;
        ss) echo "iproute2" ;;
        mtr) echo "mtr" ;;
        curl) echo "curl" ;;
        iperf3) echo "iperf3" ;;
        tcpdump) echo "tcpdump" ;;
        bc) echo "bc" ;;
        ping) echo "iputils-ping" ;;
        *) echo "" ;;
      esac ;;
    dnf|yum|zypper)
      case "$bin" in
        dig) echo "bind-utils" ;;
        ss) echo "iproute" ;;
        mtr) echo "mtr" ;;
        curl) echo "curl" ;;
        iperf3) echo "iperf3" ;;
        tcpdump) echo "tcpdump" ;;
        bc) echo "bc" ;;
        ping) echo "iputils" ;;
        *) echo "" ;;
      esac ;;
    pacman)
      case "$bin" in
        dig) echo "bind" ;;   # Arch: 'bind' provides dig
        ss) echo "iproute2" ;;
        mtr) echo "mtr" ;;
        curl) echo "curl" ;;
        iperf3) echo "iperf3" ;;
        tcpdump) echo "tcpdump" ;;
        bc) echo "bc" ;;
        ping) echo "iputils" ;;
        *) echo "" ;;
      esac ;;
    apk)
      case "$bin" in
        dig) echo "bind-tools" ;;
        ss) echo "iproute2" ;;
        mtr) echo "mtr" ;;
        curl) echo "curl" ;;
        iperf3) echo "iperf3" ;;
        tcpdump) echo "tcpdump" ;;
        bc) echo "bc" ;;
        ping) echo "iputils" ;;
        *) echo "" ;;
      esac ;;
    *)
      echo "" ;;
  esac
}

need_or_warn() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "WARN: '$1' not found. Some tests will be skipped." | tee -a "$OUTDIR/warnings.log"
    return 1
  fi
  return 0
}

# Check & interactively install missing deps
check_and_offer_install() {
  local bins=("ping" "getent" "dig" "mtr" "curl" "ss" "iperf3" "tcpdump" "bc")
  local missing_bins=()
  for b in "${bins[@]}"; do
    if ! command -v "$b" >/dev/null 2>&1; then
      missing_bins+=("$b")
    fi
  done

  if [[ ${#missing_bins[@]} -eq 0 ]]; then
    return 0
  fi

  echo "The following tools are missing: ${missing_bins[*]}"
  if [[ -z "$PKG_MGR" ]]; then
    echo "Could not detect a supported package manager automatically."
    echo "Please install the missing tools manually and re-run."
    return 0
  fi

  # Build package list
  local pkgs=()
  for b in "${missing_bins[@]}"; do
    p=$(pkg_for_bin "$b" || true)
    [[ -n "$p" ]] && pkgs+=("$p")
  done

  if [[ ${#pkgs[@]} -eq 0 ]]; then
    echo "No package mapping found for some tools on this distro. Install manually: ${missing_bins[*]}"
    return 0
  fi

  # Unique package list
  mapfile -t pkgs_unique < <(printf "%s\n" "${pkgs[@]}" | awk '!seen[$0]++')
  echo "Detected package manager: $PKG_MGR"
  echo "Packages to install: ${pkgs_unique[*]}"
  read -r -p "Install now? [Y/n] " ans
  ans=${ans:-Y}
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    if [[ -z "$SUDO" && $EUID -ne 0 ]]; then
      echo "You are not root and 'sudo' is not available. Please re-run as root or install 'sudo'."
      return 0
    fi
    # For apt, ensure update first (already embedded in INSTALL_CMD)
    set +e
    bash -c "$INSTALL_CMD ${pkgs_unique[*]}"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "Installation failed with exit code $rc. Continuing without some tools."
    fi
  else
    echo "Skipping installation as requested."
  fi
}

# Run the dependency check/offer
check_and_offer_install

echo "== netcheck.sh @ $(date) ==" | tee "$OUTDIR/summary.txt"
echo "URL=$URL  PING_TARGET=$PING_TARGET  IPERF_SERVER=${IPERF_SERVER:-none}  DURATION=${DURATION}s  UDP=$DO_UDP  TCPDUMP=${TCPDUMP_SECS}s" | tee -a "$OUTDIR/summary.txt"

#############################################
# Section 1: DNS resolution
#############################################
echo -e "\n[1] DNS resolution" | tee -a "$OUTDIR/summary.txt"
HOST_TO_RESOLVE="$(echo "$URL" | sed -E 's#^https?://##; s#/.*$##')"
if need_or_warn getent; then
  getent hosts "$HOST_TO_RESOLVE" | tee "$OUTDIR/dns_getent.txt" | tee -a "$OUTDIR/summary.txt" || true
fi
if need_or_warn dig; then
  {
    echo "A records:"
    dig +short "$HOST_TO_RESOLVE" A
    echo "AAAA records:"
    dig +short "$HOST_TO_RESOLVE" AAAA
  } | tee "$OUTDIR/dns_dig.txt" | tee -a "$OUTDIR/summary.txt" || true
fi

#############################################
# Section 2: Ping (ICMP) — latency, loss, jitter approx.
#############################################
echo -e "\n[2] Ping test to $PING_TARGET (20 probes)" | tee -a "$OUTDIR/summary.txt"
if need_or_warn ping; then
  ping -c 20 -i 0.2 "$PING_TARGET" | tee "$OUTDIR/ping.txt" || true
  LOSS=$(grep -Eo '[0-9.]+% packet loss' "$OUTDIR/ping.txt" | awk '{print $1}' || echo "n/a")
  RTT_LINE=$(grep -E 'rtt|round-trip' "$OUTDIR/ping.txt" || true)
  echo "Ping loss: ${LOSS:-n/a}; RTT: ${RTT_LINE:-n/a}" | tee -a "$OUTDIR/summary.txt"
fi

#############################################
# Section 3: MTR — per-hop loss/jitter
#############################################
echo -e "\n[3] mtr to $HOST_TO_RESOLVE (50 cycles)" | tee -a "$OUTDIR/summary.txt"
if need_or_warn mtr; then
  mtr -ezbw -c 50 "$HOST_TO_RESOLVE" | tee "$OUTDIR/mtr.txt" || true
else
  echo "mtr unavailable, skipping." | tee -a "$OUTDIR/summary.txt"
fi

#############################################
# Section 4: curl timing — TCP/TLS/TTFB
#############################################
echo -e "\n[4] curl timing to $URL (5 runs)" | tee -a "$OUTDIR/summary.txt"
if need_or_warn curl; then
  CURL_FMT=$'namelookup:%{time_namelookup}\nconnect:%{time_connect}\nappconnect:%{time_appconnect}\nstarttransfer:%{time_starttransfer}\ntotal:%{time_total}\n---\n'
  : > "$OUTDIR/curl_times.txt"
  for i in $(seq 1 5); do
    echo "# run $i" >> "$OUTDIR/curl_times.txt"
    curl -sS -o /dev/null -w "$CURL_FMT" "$URL" >> "$OUTDIR/curl_times.txt" || echo "curl failed on run $i" >> "$OUTDIR/curl_times.txt"
  done

  # Compute averages with awk
  awk '
    /^namelookup:/ {nl+=substr($0,12); c++}
    /^connect:/    {co+=substr($0,9)}
    /^appconnect:/ {ac+=substr($0,12)}
    /^starttransfer:/ {st+=substr($0,15)}
    /^total:/      {to+=substr($0,7)}
    END{
      if(c>0){
        printf "curl avg (s): namelookup=%.4f connect=%.4f tls=%.4f ttfb=%.4f total=%.4f\n", nl/c, co/c, ac/c, st/c, to/c
      } else {
        print "curl avg: n/a"
      }
    }' "$OUTDIR/curl_times.txt" | tee -a "$OUTDIR/summary.txt"
fi

#############################################
# Section 5: ss — TCP socket stats
#############################################
echo -e "\n[5] ss TCP snapshot" | tee -a "$OUTDIR/summary.txt"
if need_or_warn ss; then
  ss -ti state established | tee "$OUTDIR/ss_established.txt" >/dev/null 2>&1 || true
  echo "Saved detailed TCP socket stats to ss_established.txt" | tee -a "$OUTDIR/summary.txt"
fi

#############################################
# Section 6: iperf3 — throughput & retrans
#############################################
if [[ -n "$IPERF_SERVER" ]]; then
  echo -e "\n[6] iperf3 TCP test to $IPERF_SERVER (${DURATION}s)" | tee -a "$OUTDIR/summary.txt"
  if need_or_warn iperf3; then
    echo "[TCP upload]" | tee -a "$OUTDIR/summary.txt"
    iperf3 -c "$IPERF_SERVER" -t "$DURATION" --json > "$OUTDIR/iperf_tcp_up.json" || true
    echo "[TCP download]" | tee -a "$OUTDIR/summary.txt"
    iperf3 -c "$IPERF_SERVER" -t "$DURATION" -R --json > "$OUTDIR/iperf_tcp_down.json" || true

    # Quick summary from JSON using awk (no jq dependency)
    summarize_iperf_json() {
      local file="$1"
      local bps=$(grep -o '"bits_per_second":[0-9]*' "$file" | tail -1 | awk -F: '{print $2}')
      local retrans=$(grep -o '"retransmits":[0-9]*' "$file" | tail -1 | awk -F: '{print $2}')
      if [[ -n "$bps" ]]; then
        awk -v b="$bps" -v r="${retrans:-0}" 'BEGIN{printf "Throughput ≈ %.2f Mbps; Retransmits ≈ %d\n", b/1000000, r}'
      else
        echo "No iperf data."
      fi
    }
    echo -n "TCP upload:   " | tee -a "$OUTDIR/summary.txt"
    summarize_iperf_json "$OUTDIR/iperf_tcp_up.json" | tee -a "$OUTDIR/summary.txt"
    echo -n "TCP download: " | tee -a "$OUTDIR/summary.txt"
    summarize_iperf_json "$OUTDIR/iperf_tcp_down.json" | tee -a "$OUTDIR/summary.txt"

    if $DO_UDP; then
      echo -e "\n[UDP] iperf3 jitter/loss to $IPERF_SERVER (${DURATION}s)" | tee -a "$OUTDIR/summary.txt"
      iperf3 -u -b 0 -c "$IPERF_SERVER" -t "$DURATION" --json > "$OUTDIR/iperf_udp.json" || true
      local_jitter=$(grep -o '"jitter_ms":[0-9.]*' "$OUTDIR/iperf_udp.json" | tail -1 | awk -F: '{print $2}')
      local_loss=$(grep -o '"lost_percent":[0-9.]*' "$OUTDIR/iperf_udp.json" | tail -1 | awk -F: '{print $2}')
      echo "UDP jitter ≈ ${local_jitter:-n/a} ms; loss ≈ ${local_loss:-n/a} %" | tee -a "$OUTDIR/summary.txt"
    fi
  fi
fi

#############################################
# Section 7: Optional tcpdump capture
#############################################
if [[ "$TCPDUMP_SECS" -gt 0 ]]; then
  echo -e "\n[7] Capturing TCP traffic for ${TCPDUMP_SECS}s (root required)" | tee -a "$OUTDIR/summary.txt"
  if need_or_warn tcpdump; then
    PCAP="$OUTDIR/capture_${TCPDUMP_SECS}s.pcap"
    echo "Saving to $PCAP (tcp port 443). Press Ctrl+C to stop early." | tee -a "$OUTDIR/summary.txt"
    # shellcheck disable=SC2086
    $SUDO timeout "$TCPDUMP_SECS" tcpdump -i any tcp port 443 -w "$PCAP" >/dev/null 2>&1 || true
  fi
fi

#############################################
# Section 8: Heuristic verdict
#############################################
echo -e "\n[8] Heuristic verdict" | tee -a "$OUTDIR/summary.txt"
# Pull some numbers from earlier outputs (best-effort)
PING_LOSS_NUM=$(echo "${LOSS:-100%}" | tr -d '%' || echo "100")
TTFB_AVG=$(grep -Eo 'ttfb=[0-9. ]+' "$OUTDIR/summary.txt" | awk -F= '{print $2}' | tail -1 | awk '{print $1}' || echo "9999")

verdict="OK"
reason=""
if [[ "${PING_LOSS_NUM:-100}" != "n/a" ]]; then
  if (( $(echo "$PING_LOSS_NUM > 5" | bc -l 2>/dev/null || echo 1) )); then
    verdict="ISSUE"
    reason+="High ping loss (${PING_LOSS_NUM}%). "
  fi
fi
if [[ -n "$TTFB_AVG" ]] && (( $(echo "$TTFB_AVG > 0.6" | bc -l 2>/dev/null || echo 1) )); then
  verdict="ISSUE"
  reason+="High TTFB average (${TTFB_AVG}s). "
fi

echo "Verdict: $verdict ${reason}" | tee -a "$OUTDIR/summary.txt"

echo -e "\nDone. Results in: $OUTDIR"
echo "Open $OUTDIR/summary.txt for a one-page summary."
