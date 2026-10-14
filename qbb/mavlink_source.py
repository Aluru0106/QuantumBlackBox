"""MAVLink telemetry sources.

* ``sitl``  : listen to a real ArduPilot SITL / Pixhawk stream (udpin:0.0.0.0:14550)
* ``sim``   : built-in MAVLink telemetry simulator that emits genuine MAVLink v2 packets
              (HEARTBEAT, GLOBAL_POSITION_INT) over UDP in real time. This is a *simulator*,
              not ArduPilot; use it only when SITL is not available, and say so in the demo.
"""
from __future__ import annotations

import math
import threading
import time

from pymavlink import mavutil

WATCH = ("HEARTBEAT", "GLOBAL_POSITION_INT", "STATUSTEXT", "COMMAND_LONG", "ATTITUDE")


def run_simulator(port: int = 14550, hz: float = 2.0, stop: threading.Event | None = None):
    """Emit live MAVLink packets to udpout:127.0.0.1:<port> (a circling 'drone')."""
    mav = mavutil.mavlink_connection(f"udpout:127.0.0.1:{port}", source_system=1, source_component=1)
    t0 = time.time()
    while not (stop and stop.is_set()):
        t = time.time() - t0
        mav.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR,
                               mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 4)
        lat = int((13.0827 + 0.0005 * math.sin(t / 10)) * 1e7)
        lon = int((80.2707 + 0.0005 * math.cos(t / 10)) * 1e7)
        mav.mav.global_position_int_send(int(t * 1000), lat, lon, 50000, 30000, 0, 0, 0, 0)
        time.sleep(1 / hz)


def listen(port: int = 14550, count: int = 30, timeout: float = 30.0):
    """Yield (msg_type, text) for up to `count` watched messages."""
    m = mavutil.mavlink_connection(f"udpin:0.0.0.0:{port}")
    got, end = 0, time.time() + timeout
    while got < count and time.time() < end:
        msg = m.recv_match(type=list(WATCH), blocking=True, timeout=2)
        if msg is None:
            continue
        got += 1
        yield msg.get_type(), str(msg.to_dict())
