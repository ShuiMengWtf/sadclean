#!/usr/bin/env bash
# Clean the Nezha-abused /dev/shm backdoor family observed in this incident.
# Supported targets: CentOS, Rocky, RHEL, Debian, Ubuntu, and other systemd Linux hosts.
#
# Intended use on the infected server as root:
#   curl -fsSL https://your-domain.example/nezha_backdoor_cleanup.sh | bash
#   wget -qO- https://your-domain.example/nezha_backdoor_cleanup.sh | bash
#
# Optional flags:
#   --keep-nezha      Do not stop/disable nezha-agent.
#   --mask-nezha      Mask nezha-agent in systemd after disabling it.
#   --no-delete-shm   Preserve suspicious /dev/shm files after evidence backup.
#   --no-harden-shm   Do not remount or persist /dev/shm as noexec,nosuid,nodev.
set +e
export LC_ALL=C

: "${DISABLE_NEZHA:=1}"
: "${MASK_NEZHA:=0}"
: "${DELETE_SHM:=1}"
: "${HARDEN_SHM:=1}"

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-nezha) DISABLE_NEZHA=0 ;;
    --mask-nezha) MASK_NEZHA=1 ;;
    --no-delete-shm) DELETE_SHM=0 ;;
    --no-harden-shm) HARDEN_SHM=0 ;;
    --help|-h)
      cat <<'EOF'
Usage:
  curl -fsSL https://your-domain.example/nezha_backdoor_cleanup.sh | bash
  wget -qO- https://your-domain.example/nezha_backdoor_cleanup.sh | bash

Options:
  --keep-nezha      Do not stop/disable nezha-agent.
  --mask-nezha      Mask nezha-agent in systemd after disabling it.
  --no-delete-shm   Preserve suspicious /dev/shm files after evidence backup.
  --no-harden-shm   Do not remount or persist /dev/shm as noexec,nosuid,nodev.

Examples:
  curl -fsSL URL | bash
  curl -fsSL URL | bash -s -- --keep-nezha --no-delete-shm
EOF
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$(id -u 2>/dev/null)" != "0" ]; then
  echo "ERROR: this cleanup must be run as root." >&2
  exit 1
fi

PATTERN_RE='logger-|/dev/shm/|\.kwo|\.k.*wor.*ker.*_u|xmrig|kinsing|masscan|zgrab|pnscan|45\.196\.221\.103'
SHM_NAME_RE='(^|/)(\.kwo|\.k.*wor.*ker.*_u|.*logger.*|.*xmrig.*|.*kinsing.*|.*masscan.*|.*zgrab.*|.*pnscan.*)'
STAMP="$(date +%Y%m%d-%H%M%S)"
INCIDENT_DIR="/root/incident-nezha-backdoor-${STAMP}"
mkdir -p "$INCIDENT_DIR"
exec > >(tee -a "$INCIDENT_DIR/cleanup.log") 2>&1

have() { command -v "$1" >/dev/null 2>&1; }

backup_file() {
  [ -e "$1" ] || return 0
  cp -a "$1" "$INCIDENT_DIR/$(echo "$1" | sed 's#/#_#g').before" 2>/dev/null || true
}

comment_matching_lines() {
  file="$1"
  [ -f "$file" ] || return 0
  backup_file "$file"

  if have python3; then
    python3 - "$file" "$PATTERN_RE" <<'PY' 2>/dev/null || true
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
rx = re.compile(sys.argv[2])
lines = path.read_text(errors="replace").splitlines(True)
out, changed = [], False
for line in lines:
    if not line.lstrip().startswith("#") and rx.search(line):
        out.append("# disabled by nezha-backdoor cleanup: " + line)
        changed = True
    else:
        out.append(line)
if changed:
    path.write_text("".join(out))
PY
  elif have python; then
    python - "$file" "$PATTERN_RE" <<'PY' 2>/dev/null || true
import re, sys
path, pattern = sys.argv[1], sys.argv[2]
rx = re.compile(pattern)
data = open(path, "rb").read().decode("utf-8", "replace").splitlines(True)
out, changed = [], False
for line in data:
    if not line.lstrip().startswith("#") and rx.search(line):
        out.append("# disabled by nezha-backdoor cleanup: " + line)
        changed = True
    else:
        out.append(line)
if changed:
    open(path, "wb").write(("".join(out)).encode("utf-8"))
PY
  else
    awk -v rx="$PATTERN_RE" '$0 !~ /^[[:space:]]*#/ && $0 ~ rx {print "# disabled by nezha-backdoor cleanup: " $0; next} {print}' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
  fi
}

detect_backdoor() {
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    ppid="$(awk '/^PPid:/ {print $2}' "$p/status" 2>/dev/null || true)"
    [ "$ppid" = "2" ] && continue
    cmdline="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
    exe="$(readlink "$p/exe" 2>/dev/null || true)"
    haystack="$cmdline $exe"
    printf '%s\n' "$haystack" | grep -Eq "$PATTERN_RE" && return 0
  done

  if [ -d /dev/shm ]; then
    shm_hits="$(find /dev/shm -maxdepth 1 -xdev -type f 2>/dev/null | grep -E "$SHM_NAME_RE" | head -1)"
    [ -n "$shm_hits" ] && return 0
  fi

  for f in /etc/rc.local /etc/rc.d/rc.local /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] && awk -v rx="$PATTERN_RE" '$0 !~ /^[[:space:]]*#/ && $0 ~ rx {found=1} END{exit !found}' "$f" 2>/dev/null && return 0
  done

  crontab -l 2>/dev/null | awk -v rx="$PATTERN_RE" '$0 !~ /^[[:space:]]*#/ && $0 ~ rx {found=1} END{exit !found}' && return 0
  return 1
}

write_backdoor_report() {
  report_file="$1"
  : > "$report_file"

  {
    echo "=== remaining processes ==="
    for p in /proc/[0-9]*; do
      pid="${p##*/}"
      ppid="$(awk '/^PPid:/ {print $2}' "$p/status" 2>/dev/null || true)"
      [ "$ppid" = "2" ] && continue
      [ "$pid" = "$$" ] && continue
      cmdline="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
      exe="$(readlink "$p/exe" 2>/dev/null || true)"
      user="$(stat -c '%U' "$p" 2>/dev/null || true)"
      haystack="$cmdline $exe"
      if printf '%s\n' "$haystack" | grep -Eq "$PATTERN_RE"; then
        printf '%s %s %s %s\n' "$pid" "$ppid" "$user" "$cmdline"
      fi
    done

    echo "=== remaining /dev/shm files ==="
    if [ -d /dev/shm ]; then
      find /dev/shm -maxdepth 1 -xdev -type f 2>/dev/null | grep -E "$SHM_NAME_RE" || true
    fi

    echo "=== remaining persistence ==="
    for f in /etc/rc.local /etc/rc.d/rc.local /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
      [ -f "$f" ] && awk -v rx="$PATTERN_RE" -v file="$f" '$0 !~ /^[[:space:]]*#/ && $0 ~ rx {print file ":" NR ":" $0}' "$f" 2>/dev/null
    done
    crontab -l 2>/dev/null | awk -v rx="$PATTERN_RE" '$0 !~ /^[[:space:]]*#/ && $0 ~ rx {print "root-crontab:" NR ":" $0}' || true

    echo "=== remaining network ==="
    if have ss; then
      ss -antup 2>/dev/null | grep -E "$PATTERN_RE" || true
    elif have netstat; then
      netstat -antup 2>/dev/null | grep -E "$PATTERN_RE" || true
    fi
  } >> "$report_file"
}

if detect_backdoor; then
  if [ -t 1 ]; then
    clear 2>/dev/null || printf '\033[2J\033[H'
  fi
  echo "检测到后门存在，正在执行清理"
else
  echo "未检测到明确后门特征，继续执行检查和加固流程。"
fi

echo "=== host ==="
hostname
date -Is
uname -a
[ -f /etc/os-release ] && sed -n '1,8p' /etc/os-release
echo "incident_dir=$INCIDENT_DIR"

echo "=== backup ==="
for f in \
  /etc/rc.local \
  /etc/rc.d/rc.local \
  /etc/crontab \
  /etc/fstab \
  /root/.bash_history \
  /etc/systemd/system/nezha-agent.service \
  /lib/systemd/system/nezha-agent.service \
  /usr/lib/systemd/system/nezha-agent.service \
  /opt/nezha/agent/config.yml; do
  backup_file "$f"
done
crontab -l > "$INCIDENT_DIR/root.crontab.before" 2>/dev/null || true

echo "=== suspicious processes ==="
: > "$INCIDENT_DIR/pids.txt"
for p in /proc/[0-9]*; do
  pid="${p##*/}"
  ppid="$(awk '/^PPid:/ {print $2}' "$p/status" 2>/dev/null || true)"
  [ "$ppid" = "2" ] && continue
  cmdline="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
  exe="$(readlink "$p/exe" 2>/dev/null || true)"
  comm="$(cat "$p/comm" 2>/dev/null || true)"
  haystack="$cmdline $exe"
  if printf '%s\n' "$haystack" | grep -Eq "$PATTERN_RE"; then
    printf '%s %s %s %s\n' "$pid" "$comm" "$exe" "$cmdline" | tee -a "$INCIDENT_DIR/pids.txt"
  fi
done

echo "=== preserve samples ==="
while read -r pid _; do
  case "$pid" in ""|*[!0-9]*) continue ;; esac
  [ -e "/proc/$pid/exe" ] && cp -L "/proc/$pid/exe" "$INCIDENT_DIR/malware.$pid.bin" 2>/dev/null || cat "/proc/$pid/exe" > "$INCIDENT_DIR/malware.$pid.bin" 2>/dev/null || true
  tr '\0' ' ' < "/proc/$pid/cmdline" > "$INCIDENT_DIR/malware.$pid.cmdline" 2>/dev/null || true
  tr '\0' '\n' < "/proc/$pid/environ" > "$INCIDENT_DIR/malware.$pid.environ" 2>/dev/null || true
done < "$INCIDENT_DIR/pids.txt"

if [ -d /dev/shm ]; then
  find /dev/shm -maxdepth 1 -xdev -type f -print -exec sha256sum {} \; 2>/dev/null | tee "$INCIDENT_DIR/devshm.before.txt" || true
  find /dev/shm -maxdepth 1 -xdev -type f -size -100M 2>/dev/null | while read -r shm_file; do
    if printf '%s\n' "$shm_file" | grep -Eq "$SHM_NAME_RE"; then
      cp -a "$shm_file" "$INCIDENT_DIR/" 2>/dev/null || true
    fi
  done
fi

echo "=== persistence cleanup ==="
for f in /etc/rc.local /etc/rc.d/rc.local /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] && comment_matching_lines "$f"
done

if crontab -l >/dev/null 2>&1; then
  crontab -l 2>/dev/null | grep -Ev "$PATTERN_RE" > "$INCIDENT_DIR/root.crontab.cleaned" 2>/dev/null || true
  crontab "$INCIDENT_DIR/root.crontab.cleaned" 2>/dev/null || true
fi
chmod +x /etc/rc.local /etc/rc.d/rc.local 2>/dev/null || true

if [ "$DISABLE_NEZHA" = "1" ] && have systemctl; then
  echo "=== stop nezha ==="
  systemctl stop nezha-agent 2>/dev/null || true
  systemctl disable nezha-agent 2>/dev/null || true
  [ "$MASK_NEZHA" = "1" ] && systemctl mask nezha-agent 2>/dev/null || true
fi

echo "=== kill suspects ==="
if [ -s "$INCIDENT_DIR/pids.txt" ]; then
  awk '{print $1}' "$INCIDENT_DIR/pids.txt" | while read -r pid; do
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 2
  awk '{print $1}' "$INCIDENT_DIR/pids.txt" | while read -r pid; do
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
  done
fi

echo "=== /dev/shm cleanup ==="
if [ "$DELETE_SHM" = "1" ] && [ -d /dev/shm ]; then
  find /dev/shm -maxdepth 1 -xdev -type f \( \
    -name '.kwo*' -o -name '.k*wor*ker*' -o -name '*logger*' -o \
    -name '*xmrig*' -o -name '*kinsing*' -o -name '*masscan*' -o -name '*zgrab*' -o -name '*pnscan*' \
  \) -print -delete 2>/dev/null || true
fi

echo "=== harden /dev/shm ==="
if [ "$HARDEN_SHM" = "1" ] && [ -d /dev/shm ]; then
  echo "Applying /dev/shm nosuid,nodev,noexec hardening. Use --no-harden-shm to skip this step."
  mount | grep -q ' /dev/shm ' && mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null || true
  backup_file /etc/fstab
  if grep -Eq '^[^#].*[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
    awk 'BEGIN{OFS="\t"} /^[^#]/ && $2=="/dev/shm" {
      split($4, opts, ",")
      has_nosuid=has_nodev=has_noexec=0
      for (i in opts) {
        if (opts[i]=="nosuid") has_nosuid=1
        if (opts[i]=="nodev") has_nodev=1
        if (opts[i]=="noexec") has_noexec=1
      }
      if (!has_nosuid) $4=$4 ",nosuid"
      if (!has_nodev) $4=$4 ",nodev"
      if (!has_noexec) $4=$4 ",noexec"
    } {print}' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab
  else
    printf 'tmpfs\t/dev/shm\ttmpfs\tnosuid,nodev,noexec\t0\t0\n' >> /etc/fstab
  fi
fi

echo "=== verify ==="
FINAL_REPORT="$INCIDENT_DIR/final_backdoor_check.txt"
write_backdoor_report "$FINAL_REPORT"
cat "$FINAL_REPORT"
if awk 'NF && $0 !~ /^===/ {found=1} END{exit !found}' "$FINAL_REPORT" 2>/dev/null; then
  CLEAN_RESULT=1
  echo "回头检测结果：仍发现疑似残留，请查看 $FINAL_REPORT 并人工复查。"
else
  CLEAN_RESULT=0
  echo "回头检测结果：未发现后门特征，本次清理完成。"
fi
if have systemctl; then
  systemctl is-enabled nezha-agent 2>/dev/null || true
  systemctl is-active nezha-agent 2>/dev/null || true
fi
ls -la "$INCIDENT_DIR" 2>/dev/null || true

if [ -t 1 ]; then
  clear 2>/dev/null || printf '\033[2J\033[H'
fi
if [ "${CLEAN_RESULT:-1}" = "0" ]; then
  echo "后门清理完成，回头检测未发现残留。"
else
  echo "后门清理已执行，但回头检测发现疑似残留，请人工复查。"
  echo "检测报告：$FINAL_REPORT"
fi
cat <<'EOF'
由伤心的云提供技术支持
伤心的云 -> https://sadidc.com
你的宝藏性价比服务器
EOF
