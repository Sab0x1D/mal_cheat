
# Narrowing Malware Family Based on Artifacts

Below is a **flow-style breakdown** of how you can pivot from behavior → to suspects → to family:

---

## 1. Process Behavior & Chain *(Process Hacker / Autoruns)*

| Seen Behavior                                 | Likely Family Clues                       |
|----------------------------------------------|-------------------------------------------|
| `regsvr32.exe` spawning unknown DLL          | Remcos, Agent Tesla, FormBook             |
| `powershell.exe` with base64 payload         | AsyncRAT, CobaltStrike, Bumblebee, TA558  |
| `InstallUtil.exe`, `RegAsm.exe`, or `mshta.exe` | Agent Tesla, IcedID, GuLoader           |
| `rundll32.exe` → explorer injection          | LokiBot, ZLoader, Vidar                   |
| `wscript.exe` running `.vbs`                 | GuLoader, Lampion, Loda RAT               |
| `autoit3.exe` spawned                        | Loda RAT, TA558, DarkGate                 |
| `schtasks.exe` from a dropped EXE            | Likely persistence, seen in AsyncRAT, FormBook |

> **➡️ Action:** Use the process tree to reconstruct *initial access → loader → payload* chain. That alone narrows to 3–5 families.

---

## 2. 🛰Network Traffic & C2 Patterns *(Fiddler / Wireshark)*

| C2 Artifact                                | Family Hit                                  |
|-------------------------------------------|---------------------------------------------|
| `panel.php`, `gate.php`, `submit.php`     | FormBook, Vidar, RedLine, AsyncRAT          |
| `discord.com/api/webhooks`                | Anarchy, Blank Grabber, RisePro, Muck, Mystic |
| `telegram.org` or `t.me/`                 | Phoenix, RedLine, Lumma, Raccoon            |
| `smtp.send`, `mail.ru`, `smtp.yandex.com` | Agent Tesla, SnakeKeylogger                 |
| C2 ends in `.top`, `.xyz`, `.shop`        | Commodity malware: FormBook, LokiBot, Remcos |
| Traffic includes `key3.db`, `cookies.sqlite`, or `wallet.dat` | RedLine, Lumma, Taurus, Vidar |

> **➡️ Action:** Extract hostnames, POST URIs, or tokens.  
> If C2 path is `POST /panel.php` with `data_id=`, that screams **FormBook/Vidar/RedLine**.

---

## 3. Dropped File Content *(FileGrab / Unusual Artifacts)*

| Artifact Found                          | Family Hit                                 |
|----------------------------------------|--------------------------------------------|
| `filegrab.txt`, `dump.zip`, or `creds.log` | Phoenix, Taurus, RedLine, Raccoon         |
| `cookies.sqlite`, `logins.json`        | Any stealer, esp. Vidar, Lumma, Anarchy    |
| `.vbs` that spawns a binary            | GuLoader, Lampion, Loda RAT                |
| `.zip` contains `.lnk` + `.js`         | ModiLoader / DBatLoader, TA578, DarkGate   |
| `.ps1` or `.bat` in ZIP payload        | AsyncRAT, Amadey, AutoIT RATs              |

> **➡️ Action:** Review dropped artifacts — especially if any are archives with scripts  
> or payloads with persistence keys (check registry in parallel).

---

## 4. Strings, Configs, or Mutex Names *(PEStudio, FLOSS, strings)*

| String / Config                        | Family Clue                                 |
|---------------------------------------|---------------------------------------------|
| `AsyncMutex`, `Task_ID`, `InstallUtil`| AsyncRAT, BitRAT, Remcos                     |
| `clientid=`, `beacon=`, `malleable`   | CobaltStrike, Bazar, Metasploit             |
| `botid=`, `gate.php`, `POST /data`    | RedLine, Vidar, FormBook                    |
| `autofill`, `Discord`, `token=`       | Blank Grabber, Anarchy, Lumma, Mystic       |
| `panel.php`, `rc4key`, `taskid=`      | FormBook, Remcos, SnakeKeylogger            |

> **➡️ Action:** If you can decrypt or extract configs, hardcoded URIs, bot IDs,  
> or email credentials often uniquely fingerprint the malware.

---

## Putting It All Together: Mini Workflow Summary

1. Start with **process chain** → find suspicious child or unusual binary.  
2. Use that to pivot into **network traffic** or **dropped file** (e.g. `.vbs`, `.ps1`, etc.).  
3. Extract **strings**, config values, or exfil paths → check against cheat sheet.

Then combine with:

- Does it **persist**?
- Does it **steal creds**, **log keys**, create **overlays**?
- Is it **.NET**, **VBScript**, **AutoIt**?

You’ll almost always land in the correct malware family group (*stealer, RAT, loader*), then narrow to 1–2 names. Good luck.
