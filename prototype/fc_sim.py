#!/usr/bin/env python3
"""Tiny live MAVLink flight-controller stand-in: streams HEARTBEAT + GLOBAL_POSITION_INT at 1 Hz."""
import math, time
from pymavlink import mavutil

m = mavutil.mavlink_connection("udpout:127.0.0.1:14550", source_system=1)
t0, i = time.time(), 0
print("streaming MAVLink to udp:14550 (Ctrl-C to stop)")
while True:
    m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR,
                         mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0,
                         mavutil.mavlink.MAV_STATE_ACTIVE)
    lat = int((13.0827 + 0.0001 * math.sin(i / 10)) * 1e7)
    lon = int((80.2707 + 0.0001 * i / 50) * 1e7)
    alt = 50000 + int(1000 * math.sin(i / 5))
    m.mav.global_position_int_send(int((time.time() - t0) * 1000), lat, lon, alt, alt, 0, 0, 0, 0)
    i += 1
    time.sleep(1)
