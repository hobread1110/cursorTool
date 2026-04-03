#!/usr/bin/env python3
"""
AVN CMA 모니터 — Vehicle SW Team
SSH(Paramiko) 단일 연결, 1초 주기 exec, CmaFree 추이 + meminfo 보조 정보.
"""

from __future__ import annotations

import math
import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.widgets import Button

import paramiko

# --- 연결: dt23_log_Anal/cma_free_ssh_plot.py 의 connect_ssh / 기본값과 동일 ---
ENV_HOST = "AVN_SSH_HOST"
ENV_USER = "AVN_SSH_USER"
ENV_KEY = "AVN_SSH_KEY"
ENV_PORT = "AVN_SSH_PORT"
ENV_PASSWORD = "AVN_SSH_PASSWORD"

DEFAULT_SSH_HOST = "192.168.105.100"
DEFAULT_SSH_USER = "root"
DEFAULT_SSH_PASSWORD = "root"

SSH_HOST = DEFAULT_SSH_HOST
SSH_PORT = 22
SSH_USER = DEFAULT_SSH_USER


def connect_ssh_client() -> paramiko.SSHClient:
    """cma_free_ssh_plot.connect_ssh 와 동일한 kw 구성."""
    host = os.environ.get(ENV_HOST) or DEFAULT_SSH_HOST
    port = int(os.environ.get(ENV_PORT, "22"))
    user = os.environ.get(ENV_USER) or DEFAULT_SSH_USER
    key_file = os.environ.get(ENV_KEY, "").strip() or None
    password = os.environ.get(ENV_PASSWORD, DEFAULT_SSH_PASSWORD)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw: dict = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": 30,
        "banner_timeout": 30,
    }
    if key_file:
        kw["key_filename"] = key_file
    if password:
        kw["password"] = password
    client.connect(**kw)
    return client


# CMA 주의/위험 (kB 및 총량 대비 비율 — 단말에 맞게 조정)
CMA_WARN_FREE_KB = 50 * 1024
CMA_DANGER_FREE_KB = 20 * 1024
CMA_WARN_RATIO = 0.15
CMA_DANGER_RATIO = 0.06

WINDOW_SEC = 30
# 목표 샘플 간격(초). 실행 시간을 제외한 나머지로 sleep 해 1Hz에 맞춤
POLL_INTERVAL_SEC = 1.0
# CmaFree 그래프·CSV: 매 루프(1초). PSS Top5/composer: 이 간격마다 무거운 스크립트 실행
PSS_REFRESH_SEC = 1.0
LOG_CSV = "cma_free_log.csv"
CMA_EXEC_TIMEOUT_SEC = 15.0
# smaps_rollup 전체 순회는 무거움 — 타임아웃 여유
PSS_EXEC_TIMEOUT_SEC = 90.0

# 가벼움: 1초마다 실행 → 그래프·타임스탬프 1초 단위
CMA_ONLY_SCRIPT = r"""
set +e
CMAFREE=$(grep '^CmaFree:' /proc/meminfo 2>/dev/null | awk '{print $2}')
CMATOTAL=$(grep '^CmaTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}')
echo "CMAFREE:${CMAFREE:-}"
echo "CMATOTAL:${CMATOTAL:-}"
"""

# dt23_log_Anal/cma_free_ssh_plot.py 와 동일: /proc/*/smaps_rollup Pss 로 Total PSS Top5
PSS_COMPOSER_SCRIPT = r"""
set +e
echo PSS_TOP_BEGIN
for d in /proc/[0-9]*; do
  pid=${d##*/}
  case "$pid" in *[!0-9]*) continue ;; esac
  test -r "$d/smaps_rollup" || continue
  pss=$(awk '/^Pss:/{print $2; exit}' "$d/smaps_rollup" 2>/dev/null || true)
  test -n "$pss" || continue
  comm=$(head -c 48 "$d/comm" 2>/dev/null | tr -cd '[:print:]')
  echo "$pss $pid $comm"
done | sort -rn | head -5
echo PSS_TOP_END
echo COMPOSER_BEGIN
found=0
for d in /proc/[0-9]*; do
  pid=${d##*/}
  case "$pid" in *[!0-9]*) continue ;; esac
  test -r "$d/cmdline" || continue
  if grep -q -F "android.hardware.graphics.composer" "$d/cmdline" 2>/dev/null; then
    rss=$(awk '/^VmRSS:/{print $2}' "$d/status" 2>/dev/null || echo "0")
    test -n "$rss" || rss=0
    echo "$rss $pid"
    found=1
    break
  fi
done
if [ "$found" -eq 0 ]; then
  echo "0 0"
fi
echo COMPOSER_END
"""


def _exec_remote_script(client: paramiko.SSHClient, script: str, timeout: float) -> str:
    stdin, stdout, stderr = client.exec_command("sh -s", timeout=timeout)
    stdin.write(script.encode("utf-8"))
    stdin.channel.shutdown_write()
    out_b = stdout.read()
    err_b = stderr.read()
    text = out_b.decode("utf-8", errors="replace")
    if err_b:
        text += "\n# stderr:\n" + err_b.decode("utf-8", errors="replace")
    return text


@dataclass
class Sample:
    ts: datetime
    cma_free_kb: float
    cma_total_kb: Optional[float]
    level: str  # "ok" | "warn" | "danger"
    pss_block: str
    composer_block: str
    raw_tail: str


def classify_cma(cma_free_kb: float, cma_total_kb: Optional[float]) -> str:
    if math.isnan(cma_free_kb):
        return "danger"
    if cma_free_kb < 0 or (cma_free_kb == 0 and cma_total_kb is None):
        return "danger"
    if cma_free_kb <= CMA_DANGER_FREE_KB:
        return "danger"
    if cma_total_kb and cma_total_kb > 0:
        ratio = cma_free_kb / cma_total_kb
        if ratio <= CMA_DANGER_RATIO:
            return "danger"
    if cma_free_kb <= CMA_WARN_FREE_KB:
        return "warn"
    if cma_total_kb and cma_total_kb > 0:
        ratio = cma_free_kb / cma_total_kb
        if ratio <= CMA_WARN_RATIO:
            return "warn"
    return "ok"


def parse_cma_only(text: str) -> tuple[float, Optional[float]]:
    cma_free: Optional[float] = None
    cma_total: Optional[float] = None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("CMAFREE:"):
            v = line.split(":", 1)[1].strip()
            if v.isdigit():
                cma_free = float(v)
        elif line.startswith("CMATOTAL:"):
            v = line.split(":", 1)[1].strip().replace(",", "")
            if v.isdigit():
                cma_total = float(v)
    if cma_free is None:
        cma_free = float("nan")
    return cma_free, cma_total


def parse_pss_composer_blocks(text: str) -> tuple[str, str]:
    pss_rows: list[tuple[int, int, str]] = []
    composer_rss: Optional[int] = None
    composer_pid: Optional[int] = None
    mode: Optional[str] = None

    for line in text.splitlines():
        line = line.rstrip("\r")
        if line == "PSS_TOP_BEGIN":
            mode = "pss"
            continue
        if line == "PSS_TOP_END":
            mode = None
            continue
        if line == "COMPOSER_BEGIN":
            mode = "composer"
            continue
        if line == "COMPOSER_END":
            mode = None
            continue
        if mode == "pss" and line.strip():
            parts = line.split(None, 2)
            try:
                if len(parts) >= 3:
                    pss_rows.append((int(parts[0]), int(parts[1]), parts[2]))
                elif len(parts) == 2:
                    pss_rows.append((int(parts[0]), int(parts[1]), "?"))
            except ValueError:
                continue
        elif mode == "composer" and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                r, p = int(parts[0]), int(parts[1])
                if r == 0 and p == 0:
                    composer_rss, composer_pid = None, None
                else:
                    composer_rss, composer_pid = r, p

    pss_lines_fmt: list[str] = []
    for pss_kb, pid, comm in pss_rows[:5]:
        pss_lines_fmt.append(f"  {pss_kb:>8} kB  PSS    pid {pid:<6}  {comm}")
    pss_block = (
        "\n".join(pss_lines_fmt)
        if pss_lines_fmt
        else "(Top5 없음 — /proc/*/smaps_rollup 권한·커널 지원 확인)"
    )

    if composer_rss is not None and composer_pid is not None:
        comp_block = f"  VmRSS {composer_rss} kB    pid {composer_pid}    android.hardware.graphics.composer"
    else:
        comp_block = "(android.hardware.graphics.composer 프로세스 없음)"
    return pss_block, comp_block


def build_sample(
    cma_free: float,
    cma_total: Optional[float],
    pss_block: str,
    composer_block: str,
    raw_tail: str = "",
) -> Sample:
    level = classify_cma(cma_free, cma_total)
    return Sample(
        ts=datetime.now(),
        cma_free_kb=cma_free,
        cma_total_kb=cma_total,
        level=level,
        pss_block=pss_block,
        composer_block=composer_block,
        raw_tail=raw_tail,
    )


def append_csv(sample: Sample) -> None:
    exists = os.path.isfile(LOG_CSV)
    with open(LOG_CSV, "a", encoding="utf-8") as f:
        if not exists:
            f.write("timestamp,cma_free_kb,cma_total_kb,level\n")
        tot = "" if sample.cma_total_kb is None else f"{sample.cma_total_kb:.0f}"
        f.write(
            f"{sample.ts.isoformat(timespec='seconds')},{sample.cma_free_kb:.0f},{tot},{sample.level}\n"
        )


class SSHPoller(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self._stop = threading.Event()
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()
        self.q: queue.Queue = queue.Queue(maxsize=2)
        self.last_error: Optional[str] = None
        self._pss_block: str = "(Top5 수집 전…)"
        self._composer_block: str = "(composer 수집 전…)"
        self._last_pss_ts: float = -1e9

    @property
    def client(self) -> Optional[paramiko.SSHClient]:
        with self._lock:
            return self._client

    def connect(self) -> None:
        try:
            c = connect_ssh_client()
        except Exception as e:
            raise OSError(
                "SSH 로그인에 실패했습니다. "
                "cma_free_ssh_plot 과 동일하게 AVN_SSH_* 및 기본 비밀번호 root 를 확인하세요."
            ) from e

        t = c.get_transport()
        if t:
            t.set_keepalive(30)

        with self._lock:
            old = self._client
            self._client = c
        if old:
            try:
                old.close()
            except Exception:
                pass
        self.last_error = None

    def disconnect(self) -> None:
        with self._lock:
            c = self._client
            self._client = None
        if c:
            try:
                c.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            cli = self.client
            if cli is None:
                time.sleep(0.3)
                continue
            t_loop = time.monotonic()
            try:
                cma_text = _exec_remote_script(cli, CMA_ONLY_SCRIPT, CMA_EXEC_TIMEOUT_SEC)
                cma_free, cma_total = parse_cma_only(cma_text)

                now = time.monotonic()
                if now - self._last_pss_ts >= PSS_REFRESH_SEC:
                    pss_text = _exec_remote_script(
                        cli, PSS_COMPOSER_SCRIPT, PSS_EXEC_TIMEOUT_SEC
                    )
                    self._pss_block, self._composer_block = parse_pss_composer_blocks(
                        pss_text
                    )
                    self._last_pss_ts = now

                sample = build_sample(
                    cma_free,
                    cma_total,
                    self._pss_block,
                    self._composer_block,
                    raw_tail=cma_text[-200:] if len(cma_text) > 200 else cma_text,
                )
                append_csv(sample)
                try:
                    self.q.put_nowait(sample)
                except queue.Full:
                    try:
                        self.q.get_nowait()
                    except queue.Empty:
                        pass
                    self.q.put_nowait(sample)
                self.last_error = None
            except Exception as e:
                self.last_error = str(e)
                try:
                    self.q.put_nowait(("error", str(e)))
                except queue.Full:
                    pass
                self.disconnect()
            elapsed = time.monotonic() - t_loop
            time.sleep(max(0.0, POLL_INTERVAL_SEC - elapsed))


def main() -> None:
    poller = SSHPoller()
    status_ref: dict[str, str] = {"ssh_red": ""}
    try:
        poller.connect()
    except Exception as e:
        poller.last_error = str(e)
        status_ref["ssh_red"] = "단말에 연결되지 않았습니다"

    poller.start()

    # 데이터: 최근 30초(샘플 최대 30개)
    times: deque[datetime] = deque(maxlen=WINDOW_SEC)
    values: deque[float] = deque(maxlen=WINDOW_SEC)
    levels: deque[str] = deque(maxlen=WINDOW_SEC)
    last_sample: list[Optional[Sample]] = [None]

    plt.rcParams["font.family"] = ["Malgun Gothic", "DejaVu Sans", "sans-serif"]

    fig = plt.figure(figsize=(11, 8))
    fig.canvas.manager.set_window_title("Vehicle SW Team — CMA Monitor")
    fig.suptitle(
        "Vehicle SW Team — CmaFree / CmaTotal (kB) / AVN",
        fontsize=13,
        fontweight="bold",
    )

    # 그래프·하단 정보 사이 여백: 그래프 bottom 을 올려 간격 확보 (figure 좌표)
    ax_line = fig.add_axes([0.08, 0.46, 0.84, 0.39])
    ax_info = fig.add_axes([0.08, 0.05, 0.84, 0.30])
    ax_info.axis("off")

    (line,) = ax_line.plot([], [], linewidth=2.0, color="tab:blue")
    ax_line.set_xlabel("시간")
    ax_line.set_ylabel("CmaFree (kB)")
    ax_line.grid(True, alpha=0.3)
    ax_line.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))

    info_text = ax_info.text(
        0.0,
        1.0,
        "",
        transform=ax_info.transAxes,
        va="top",
        ha="left",
        fontsize=9,
        family="Malgun Gothic",
        wrap=True,
    )

    btn_ax = fig.add_axes([0.82, 0.92, 0.12, 0.05])
    btn = Button(btn_ax, "재접속")

    # 재접속 버튼 바로 아래: SSH 끊김·재접속 안내 (붉은색)
    ax_ssh_banner = fig.add_axes([0.76, 0.848, 0.22, 0.068])
    ax_ssh_banner.axis("off")
    ssh_banner = ax_ssh_banner.text(
        0.5,
        0.5,
        "",
        transform=ax_ssh_banner.transAxes,
        ha="center",
        va="center",
        fontsize=9,
        color="red",
        family="Malgun Gothic",
    )

    def on_reconnect(_event) -> None:
        status_ref["ssh_red"] = "재접속 중…"
        ssh_banner.set_text(status_ref["ssh_red"])
        fig.canvas.draw_idle()
        try:
            poller.disconnect()
            poller.connect()
            status_ref["ssh_red"] = ""
        except Exception:
            status_ref["ssh_red"] = "재접속 실패"
        ssh_banner.set_text(status_ref["ssh_red"])
        fig.canvas.draw_idle()

    btn.on_clicked(on_reconnect)

    def animate(_frame: int) -> None:
        # 큐에 쌓인 최신 샘플 반영
        latest: Optional[Sample] = None
        while True:
            try:
                item = poller.q.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, tuple) and item[0] == "error":
                status_ref["ssh_red"] = "연결 끊김 — 재접속 버튼을 누르세요"
                continue
            latest = item

        if poller.client:
            status_ref["ssh_red"] = ""

        if latest is not None:
            last_sample[0] = latest
            times.append(latest.ts)
            values.append(latest.cma_free_kb)
            levels.append(latest.level)

        if times:
            xs = list(times)
            ys = list(values)
            line.set_data(xs, ys)
            ax_line.relim()
            ax_line.autoscale_view()
            fig.autofmt_xdate()

            cur_level = levels[-1] if levels else "ok"
            if cur_level == "danger":
                line.set_color("red")
                ax_line.set_facecolor("#fff0f0")
            elif cur_level == "warn":
                line.set_color("red")
                ax_line.set_facecolor("#fff8f0")
            else:
                line.set_color("tab:blue")
                ax_line.set_facecolor("white")

            s = last_sample[0]
            if s.cma_total_kb is not None and not math.isnan(s.cma_total_kb):
                tot_disp = f"{s.cma_total_kb:.0f} kB"
            else:
                tot_disp = "—"
            free_disp = (
                f"{s.cma_free_kb:.0f} kB"
                if not math.isnan(s.cma_free_kb)
                else "—"
            )
            cma_hdr = f"CmaFree: {free_disp}  |  CmaTotal: {tot_disp}\n"
            hdr = (
                cma_hdr
                + f"최근 {WINDOW_SEC}s · 그래프·CMA 갱신 {POLL_INTERVAL_SEC}s · PSS Top5 갱신 {PSS_REFRESH_SEC}s\n"
                + f"주의: CmaFree≤{CMA_WARN_FREE_KB//1024}MB 또는 비율≤{CMA_WARN_RATIO:.0%}  |  "
                + f"위험: ≤{CMA_DANGER_FREE_KB//1024}MB 또는 ≤{CMA_DANGER_RATIO:.0%}\n"
                + ("-" * 72 + "\n")
            )
            if s:
                block = (
                    hdr
                    + "[ Total PSS by Process Top5 ]\n"
                    + s.pss_block
                    + "\n"
                    + ("-" * 72)
                    + "\n[ android.hardware.graphics.composer ]\n"
                    + s.composer_block
                )
            else:
                block = hdr + "데이터 수신 대기 중…"
            info_text.set_text(block)
            fig.suptitle(
                f"Vehicle SW Team — CmaFree {free_disp} / CmaTotal {tot_disp} / AVN",
                fontsize=13,
                fontweight="bold",
            )
        else:
            info_text.set_text("데이터 수신 대기 중…")

        ssh_banner.set_text(status_ref.get("ssh_red", ""))

        fig.canvas.draw_idle()

    timer = fig.canvas.new_timer(interval=1000)
    timer.add_callback(animate, 0)
    timer.start()
    animate(0)

    plt.show()
    poller.stop()
    poller.disconnect()


if __name__ == "__main__":
    main()
