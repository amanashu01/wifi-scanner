"""
Traffic (bandwidth) monitor
===========================
Reads the byte/packet counters the kernel keeps for every network interface
and turns two consecutive readings into a rate (bytes per second).

  rate = (bytes_now - bytes_before) / (time_now - time_before)

This is the same technique used by tools like `nload`, `iftop` (totals) or the
Activity Monitor "Network" tab. No packets are captured - only counters are read.
"""

import threading
import time

try:
    import psutil
except ImportError:
    psutil = None

_lock = threading.Lock()
_last = {"t": None, "counters": {}}


def _read():
    return {name: c._asdict() for name, c in psutil.net_io_counters(pernic=True).items()}


def sample():
    """Return current per-interface totals and rates since the previous call."""
    if psutil is None:
        raise RuntimeError("psutil is required for traffic stats: pip install psutil")

    now = time.monotonic()
    counters = _read()
    with _lock:
        prev_t, prev = _last["t"], _last["counters"]
        _last["t"], _last["counters"] = now, counters

    dt = (now - prev_t) if prev_t else None
    interfaces = []
    total_in = total_out = 0.0
    for name, c in counters.items():
        p = prev.get(name)
        if dt and p:
            rx = max(c["bytes_recv"] - p["bytes_recv"], 0) / dt
            tx = max(c["bytes_sent"] - p["bytes_sent"], 0) / dt
        else:
            rx = tx = 0.0
        # loopback traffic never leaves the machine - keep it out of the totals
        if not name.startswith(("lo", "Loopback")):
            total_in += rx
            total_out += tx
        interfaces.append({
            "name": name,
            "rx_rate": rx,
            "tx_rate": tx,
            "bytes_recv": c["bytes_recv"],
            "bytes_sent": c["bytes_sent"],
            "packets_recv": c["packets_recv"],
            "packets_sent": c["packets_sent"],
            "errin": c["errin"],
            "errout": c["errout"],
            "dropin": c["dropin"],
            "dropout": c["dropout"],
        })

    interfaces.sort(key=lambda i: i["bytes_recv"] + i["bytes_sent"], reverse=True)
    return {"rx_rate": total_in, "tx_rate": total_out, "interfaces": interfaces,
            "ts": time.time()}
