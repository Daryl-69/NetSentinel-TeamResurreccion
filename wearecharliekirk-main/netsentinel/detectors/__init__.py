"""Rule-based and statistical detectors added for PS 26145.

beacon_score   C2 beaconing: combined periodicity score (live)
ddos_volume    DDoS: per-destination rate, source-IP entropy, attack family
dns_behaviour  DGA / DNS tunnelling: NXDOMAIN rate, record-type mix, fan-out
tls_sessions   Encrypted-session malware: JA3/JA4 rarity, size/timing regularity
exfil_ratio    Exfiltration: out/in byte ratio of outbound connections
"""
