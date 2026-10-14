"""Extract REAL sensor telemetry from a public PX4 flight log (pyulog test/sample.ulg, AUAV-X2 hardware, 69 s)
into a small CSV at 10 Hz: attitude (from quaternion), gyro, accelerometer, magnetometer."""
import numpy as np, csv
from pyulog import ULog
u = ULog('data/sample.ulg'); g = {d.name: d.data for d in u.data_list}
t0 = u.start_timestamp
q = np.array([g['vehicle_attitude'][f'q[{i}]'] for i in range(4)]).T
ta = (np.array(g['vehicle_attitude']['timestamp']) - t0) / 1e6
w, x, y, z = q.T
roll = np.arctan2(2*(w*x+y*z), 1-2*(x*x+y*y)); pitch = np.arcsin(np.clip(2*(w*y-z*x), -1, 1)); yaw = np.arctan2(2*(w*z+x*y), 1-2*(y*y+z*z))
s = g['sensor_combined']; ts = (np.array(s['timestamp']) - t0) / 1e6
rows = []
for t in np.arange(max(ta[0], ts[0]), min(ta[-1], ts[-1]), 0.1):
    ia = np.searchsorted(ta, t); isx = np.searchsorted(ts, t)
    ia = min(ia, len(ta)-1); isx = min(isx, len(ts)-1)
    rows.append([round(t, 3), roll[ia], pitch[ia], yaw[ia],
                 s['gyro_rad[0]'][isx], s['gyro_rad[1]'][isx], s['gyro_rad[2]'][isx],
                 s['accelerometer_m_s2[0]'][isx], s['accelerometer_m_s2[1]'][isx], s['accelerometer_m_s2[2]'][isx],
                 s['magnetometer_ga[0]'][isx], s['magnetometer_ga[1]'][isx], s['magnetometer_ga[2]'][isx]])
with open('qbb/real_telemetry.csv', 'w', newline='') as f:
    wr = csv.writer(f); wr.writerow(['t_s','roll_rad','pitch_rad','yaw_rad','gyro_x','gyro_y','gyro_z','acc_x','acc_y','acc_z','mag_x','mag_y','mag_z'])
    for r in rows: wr.writerow([f'{v:.6f}' for v in r])
print(len(rows), 'rows at 10 Hz,', rows[-1][0], 's')
