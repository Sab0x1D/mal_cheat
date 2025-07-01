
# How to Use This Matrix

**Step 1:** Observe processes (Process Hacker, Autoruns)  
**Step 2:** Identify C2 patterns (URIs, domains, traffic in Fiddler)  
**Step 3:** Cross-reference with this matrix → shortlist suspects  
**Step 4:** Confirm with strings, dropped files, mutexes, or config

---

| 🔍 Process / Artifact        | 🌐 C2 Pattern / String           | 💀 Suspected Malware Family          | 🧠 Behavior / Notes                                                  |
|-----------------------------|----------------------------------|--------------------------------------|---------------------------------------------------------------------|
| regasm.exe, InstallUtil.exe | smtp.yandex.com, Send-Mail       | Agent Tesla, SnakeKeylogger          | .NET stealer, SMTP exfil, logs to .zip/.txt                         |
| powershell -EncodedCommand  | pastebin.com/raw/                | AsyncRAT, njRAT, Remcos              | Base64 config or payload, remote code exec                          |
| rundll32.exe, mshta.exe     | gate.php, panel.php              | FormBook, RedLine, Vidar             | Common POST exfil path, classic stealers                            |
| wscript.exe + .vbs          | cloudfront.net, onedrive         | Lampion, GuLoader, TA578             | Script loader to DLL or EXE, 2nd stage delivery                     |
| autoit3.exe                 | task_id=, bot_id=                | Loda RAT, DarkGate, TA558            | AutoIt dropper, likely chained from VBS or shortcut                 |
| python.exe, pyinstaller.exe| token=, wallet.dat               | Mystic, Muck, BlankGrabber           | Python stealers, grabs Discord tokens, browser wallets              |
| chrome.exe + inject.js     | login=, inject.html              | TrickBot, IcedID, ZLoader            | Banking trojans w/ web inject overlays                              |
| schtasks.exe, cmd.exe      | panel.php, task.php              | AsyncRAT, Remcos, njRAT              | Scheduled tasks as persistence & loader                             |
| discord.com/api/webhooks   | token=, cookies.sqlite           | Anarchy, Mystic, RisePro             | Discord exfil, often bundled in Python stealers                     |
| ftp.send(), smtp.send()    | creds.zip, dump.txt              | Agent Tesla, LokiBot                 | FTP/SMTP exfil of dumped data                                       |
| .docm + cmd + powershell   | config.ini, submit.php           | LokiBot, Remcos                      | Macro dropper chain, .ini config used in Lokibot                    |
| .lnk + .vbs + shortcut.exe | gate.php, cloudfront             | Lampion, RATicate, TA578             | LNK chain into loader (VBS or AutoIt)                               |
| dropped: cookies.sqlite    | POST /panel.php                  | Lumma, RedLine, Taurus               | Browser stealer families, includes autofill/cookie grab             |
| .ps1 → rundll32.exe        | payload.dll                      | Bumblebee, CobaltStrike              | Powershell loaders → DLL stage → often ransomware                   |
| telegram.org or t.me/      | TelegramToken                    | Lumma, Raccoon, RedLine              | Telegram-based exfil seen in wallet grabbers                        |
| python.exe → grabbed.txt   | grabbed.txt, wallet.dat          | Mystic, Muck, RisePro                | Drops plain text loot file locally before upload                    |
| MSI → loader → ransomware  | beacon=, botid=                  | Bumblebee, ZLoader                   | Staged loader often used pre-ransomware                             |
| explorer.exe → injected thread | key3.db, cookies.sqlite      | Vidar, Lumma, Taurus                 | Browser data stealers inject into explorer/svchost                  |
| wevtutil.exe, log deletion | (none)                           | ZeroLogs, APTs, Cobalt Strike        | Anti-forensics/log clearing post-exec                               |
| .bat + powershell + .vbs   | panel.php, api.php               | TA578, TA558, ModiLoader             | Script-based loader chains seen in email/phishing                   |
