**Yes—the main change is to replace snaplen `512` with full-packet capture (`-s 0`), then verify that the scheduled task actually uses the updated setting.** Also fix the retention assumptions: your ring buffer limits storage, but **does not guarantee that all 12 days survive**.

I only have the commands you pasted, not the actual `.ps1` contents, so the file changes below are search-and-edit instructions—not a verified patch.

## 1. Change the actual `dumpcap` command

### Current command

```powershell
dumpcap.exe -i <interface> -w D:\capture\ns.pcap `
  -b duration:3600 -b files:<N> -b filesize:200000 -s 512
```

### Recommended command for your authorized research capture

```powershell
dumpcap.exe -i <interface> -w D:\capture\ns.pcapng `
  -b duration:3600 -b files:<N> -b filesize:200000 -s 0
```

Changes:

| Setting | Change | Reason |
|---|---|---|
| `-s 512` | **`-s 0`** | Capture complete packets; avoid truncating TLS ClientHellos |
| `ns.pcap` | `ns.pcapng` | Match dumpcap’s usual default output format; the extension itself does not select the format |
| Rotation settings | Keep initially | Reasonable, but monitor retention and disk usage |

**Correction to the previous instructions:** `-s 512` is **not “headers only, no payload”** and is **not guaranteed to capture TLS SNI**. It captures the first 512 bytes of each packet, which can include application content while still truncating large handshake packets.

Full capture can contain sensitive data. Use it only on authorized machines/networks, restrict access, and retain extracted metadata rather than raw packets longer than necessary. No snaplen setting guarantees “metadata only.”

---

## 2. Find where `512` is set in your scripts

Run:

```powershell
Set-Location 'D:\1_sih26#2\netsentinel-main\v2'

$files = @(
    '.\start_capture.ps1',
    '.\capture_service.ps1',
    '.\install_capture_task.ps1'
)

Select-String -LiteralPath $files `
  -Pattern '512|snaplen|dumpcap|filesize|duration|MaxGB|\.pcap' `
  -Context 2,2
```

Back up the scripts before editing:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

foreach ($file in $files) {
    Copy-Item -LiteralPath $file -Destination "${file}.${stamp}.bak"
}
```

### In `start_capture.ps1` and `capture_service.ps1`

Look for **whichever form your code uses**:

```powershell
-s 512
```

or:

```powershell
"-s", "512"
```

or:

```powershell
$Snaplen = 512
```

Change the corresponding setting to:

```powershell
-s 0
```

or:

```powershell
"-s", "0"
```

or:

```powershell
$Snaplen = 0
```

Update comments too:

```powershell
# Full-packet research capture.
# May contain sensitive payload; apply access and retention controls.
```

**Do not globally replace every occurrence of `512`**—only the capture setting and related documentation.

### In `install_capture_task.ps1`

Check whether it:

- Embeds the dumpcap arguments.
- Passes a snaplen parameter.
- Copies `capture_service.ps1` to another directory.
- Merely schedules the existing service script.

If it embeds `512`, change it. If it installs a copy, reinstall/update that copy using the installer. Editing your source file alone would not update an installed copy.

---

## 3. Check filename compatibility before switching to `.pcapng`

Your converter may search only for `*.pcap`.

Check:

```powershell
Select-String -LiteralPath '.\zeekify.sh' `
  -Pattern 'pcap|find|glob' -Context 2,2
```

If it searches only for `.pcap`, update discovery to include both extensions. For example, a shell `find` expression could be:

```bash
find "$INPUT_DIR" -type f \( -name '*.pcap' -o -name '*.pcapng' \)
```

Adapt that to the script’s existing loop; do not paste it blindly over the entire converter.

**For the smallest immediate change, leave the existing filename unchanged and change only `-s 512` to `-s 0`.** Then address format naming separately after a conversion test.

---

## 4. Restart capture—the running process will not change automatically

First inspect the currently running command:

```powershell
Get-CimInstance Win32_Process -Filter "Name='dumpcap.exe'" |
    Select-Object ProcessId, ExecutablePath, CommandLine |
    Format-List
```

This tells you:

- Whether capture is still running.
- Which interface it uses.
- Whether it actually has `-s 512`.
- Where it writes output.

Then:

1. Stop capture using your script’s documented stop mechanism. For an interactive dumpcap session, use **Ctrl+C**.
2. Update the scripts.
3. Reinstall/update the scheduled task if it uses copied files or embedded arguments.
4. Restart capture.
5. Run the process-inspection command again and confirm **`-s 0`**.

Your pasted instructions list:

```powershell
.\install_capture_task.ps1 -Status
.\install_capture_task.ps1 -Uninstall
```

However, **I cannot tell from the name whether `-Uninstall` also stops an already-running dumpcap process**. Verify that before starting another capture.

Avoid two concurrent writers to the same output location.

### Start the corrected capture in a separate folder

```powershell
.\start_capture.ps1 -Interface 5 `
  -OutDir 'D:\capture-full' -MaxGB 40
```

For persistent capture, after confirming the previous task/process is stopped:

```powershell
.\install_capture_task.ps1 -Interface 5 `
  -OutDir 'D:\capture-full' -MaxGB 40
```

Using a new folder preserves the distinction between truncated and corrected captures.

---

## 5. Fix the “12-day dataset” retention problem

These options:

```text
-b duration:3600
-b filesize:200000
```

mean **rotate after one hour OR approximately 200 MB, whichever happens first**.

Therefore:

- Files may cover much less than one hour.
- `<N>` files do not necessarily represent `<N>` hours.
- Full capture can fill the ring faster than the previous truncated capture.
- `-MaxGB 40` is a storage budget, not a duration guarantee.

For your dataset:

> **Archive completed capture files outside the ring directory before they are overwritten.**

Do not move the file currently being written. A later improvement is to make the service track completed files and archive them automatically.

Measure actual storage use for several representative hours:

```powershell
$bytes = (
    Get-ChildItem 'D:\capture-full' -File |
    Measure-Object -Property Length -Sum
).Sum

'{0:N2} GiB currently stored' -f ($bytes / 1GB)
```

Use measured daily volume to size the archive. Keep hashes and a manifest of capture settings for reproducibility.

---

## 6. Keep your browser policies—for the controlled experiment only

Your QUIC/DoH policy commands can remain for the **controlled-visibility dataset**.

After applying them:

- Restart Chrome/Edge.
- Verify effective settings at `chrome://policy` or `edge://policy`.
- Check other applications and OS-level encrypted DNS separately.

But change the documentation from:

> “Required for hostname visibility.”

to:

> “Controlled-lab settings to improve naming visibility; not a universal production requirement or guarantee.”

QUIC can sometimes be passively parsed by compatible analyzers; ECH can still hide the real hostname. Browser policies do not control every application.

Later, collect a separately labeled dataset with normal settings enabled.

---

## 7. Validate with a short capture before leaving it running

After 10–15 minutes, inspect a **completed** capture file.

If Wireshark is installed at the usual location:

```powershell
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
$pcap = 'D:\capture-full\<completed-file>.pcapng'
```

### Check capture truncation

```powershell
& $tshark -r $pcap `
  -Y 'frame.cap_len < frame.len' `
  -T fields -e frame.number |
  Measure-Object -Line
```

Ideally this reports zero truncated packets. It does **not** measure capture drops.

### Check observable TLS SNI

```powershell
& $tshark -r $pcap `
  -Y 'tls.handshake.extensions_server_name' `
  -T fields -e tls.handshake.extensions_server_name |
  Sort-Object -Unique
```

### Check visible DNS queries

```powershell
& $tshark -r $pcap `
  -Y 'dns.flags.response == 0' `
  -T fields -e dns.qry.name |
  Sort-Object -Unique
```

Then run your existing Zeek conversion on the pilot and confirm the **Zeek loader**, not just Wireshark, recovers names correctly.

## What to change now, in order

1. **Inspect the running dumpcap command.**
2. **Change snaplen to `0` in both interactive and persistent capture paths.**
3. **Restart and verify the effective command.**
4. **Capture into a new directory.**
5. **Run the short truncation/SNI/DNS/Zeek checks.**
6. **Archive completed files so the ring cannot erase your dataset.**

You do **not** need to retrain models or rewrite the pipeline merely to make these capture corrections. First establish that the new capture produces complete, usable observations.
