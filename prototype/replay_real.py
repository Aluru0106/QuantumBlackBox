#!/usr/bin/env python3
"""Replay REAL sensor telemetry (recorded on a real PX4 flight controller) as live MAVLink over UDP 14550.

  python3 replay_real.py [HZ]      default 2 messages-sets per second (real log is 10 Hz, 69 s)
Sends ATTITUDE + HIGHRES_IMU for each real sample, and a HEARTBEAT once per second.
Data source: PX4/pyulog test/sample.ulg (public, BSD-3), hardware AUAV-X2, converted by prep_data.py.
"""
import csv, sys, time
from pymavlink import mavutil

hz = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
rows = list(csv.DictReader(open("real_telemetry.csv")))
m = mavutil.mavlink_connection("udpout:127.0.0.1:14550", source_system=1)
print(f"replaying {len(rows)} REAL samples from a real PX4 flight controller at {hz} Hz -> udp:14550 (Ctrl-C to stop)")
last_hb = 0.0
for i, r in enumerate(rows):
    f = {k: float(v) for k, v in r.items()}
    if time.time() - last_hb >= 1.0:
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR, mavutil.mavlink.MAV_AUTOPILOT_PX4, 0, 0,
                             mavutil.mavlink.MAV_STATE_ACTIVE)
        last_hb = time.time()
    m.mav.attitude_send(int(f["t_s"] * 1000), f["roll_rad"], f["pitch_rad"], f["yaw_rad"],
                        f["gyro_x"], f["gyro_y"], f["gyro_z"])
    m.mav.highres_imu_send(int(f["t_s"] * 1e6), f["acc_x"], f["acc_y"], f["acc_z"],
                           f["gyro_x"], f["gyro_y"], f["gyro_z"], f["mag_x"], f["mag_y"], f["mag_z"],
                           0, 0, 0, 0, 0x1FF)
    print(f"t={f['t_s']:6.1f}s roll={f['roll_rad']*57.2958:6.1f} deg pitch={f['pitch_rad']*57.2958:6.1f} deg", end="\r")
    time.sleep(1.0 / hz)
print("\nend of real flight data")
