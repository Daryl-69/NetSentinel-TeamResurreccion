import pandas as pd, numpy as np
ref = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
our = pd.read_csv('ours.csv')
ref.columns = [c.strip() for c in ref.columns]

print('=== Flow Size (packets per flow) ===')
print(f'CIC  Total Fwd Packets: mean={ref["Total Fwd Packets"].mean():.1f}  median={ref["Total Fwd Packets"].median():.1f}')
print(f'Ours Total Fwd Packets: mean={our["Total Fwd Packets"].mean():.1f}  median={our["Total Fwd Packets"].median():.1f}')

print('\n=== Packet Size ===')
print(f'CIC  Fwd Packet Length Min: mean={ref["Fwd Packet Length Min"].mean():.1f}')
print(f'Ours Fwd Packet Length Min: mean={our["Fwd Packet Length Min"].mean():.1f}')

print('\n=== ACK flag (should now be binary) ===')
print(f'CIC  ACK max={ref["ACK Flag Count"].max()}  mean={ref["ACK Flag Count"].mean():.3f}')
print(f'Ours ACK max={our["ACK Flag Count"].max()}  mean={our["ACK Flag Count"].mean():.3f}')

print('\n=== SYN flag ===')
print(f'CIC  SYN mean={ref["SYN Flag Count"].mean():.3f}')
print(f'Ours SYN mean={our["SYN Flag Count"].mean():.3f}')

print('\n=== Flow Packets/s (rate fix) ===')
print(f'CIC  median={ref["Flow Packets/s"].median():.1f}  mean={ref["Flow Packets/s"].mean():.1f}  max={ref["Flow Packets/s"].max():.0f}')
print(f'Ours median={our["Flow Packets/s"].median():.1f}  mean={our["Flow Packets/s"].mean():.1f}  max={our["Flow Packets/s"].max():.0f}')
