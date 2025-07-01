Malware Family Cheatsheet (PDC Style + Paths & Processes)

---

### 🧬 Agent Tesla (Stealer)

**Behavior:**
- .NET-based stealer and keylogger.
- Steals credentials from browsers, VPNs, FTP/email clients.
- Exfiltrates data via SMTP or HTTP POST.

**Behavior Path:**
- `dropper.exe → regasm.exe → SMTP exfil`

**Spawned Processes:**
- `regasm.exe`, `InstallUtil.exe`, `cmd.exe`

**Known C2 / Strings:**
- `smtp.yandex.com`, `Send-MailMessage`, `token=`, `credentials.xml`

---

### 🧬 AsyncRAT (RAT)

**Behavior:**
- .NET-based RAT with TLS C2.
- Keylogging, screen capture, file ops.
- Often obfuscated with CryptoObfuscator.

**Behavior Path:**
- `payload.exe → InstallUtil.exe → async_beacon`

**Spawned Processes:**
- `InstallUtil.exe`, `powershell.exe`, `cmd.exe`

**Known C2 / Strings:**
- `AES_Key=`, `asyncgate.xyz`, `pastebin.com/raw`

---

### 🧬 TrickBot (Banking Trojan / Loader)

**Behavior:**
- Credential dumping, recon, lateral movement.
- Modular loader used with Ryuk, Emotet.

**Behavior Path:**
- `Office macro → rundll32.exe → svchost injection`

**Spawned Processes:**
- `rundll32.exe`, `svchost.exe`, `taskschd.msc`

**Known C2 / Strings:**
- `group_tag=`, `mod=loader`, `.biz`, `.pw`

---

### 🧬 Remcos (RAT)

**Behavior:**
- Commercial RAT for full remote control.
- Webcam/mic access, keystrokes, persistence.

**Behavior Path:**
- `remcos.exe → vbc.exe → registry runkey`

**Spawned Processes:**
- `vbc.exe`, `cmd.exe`, `explorer.exe`

**Known C2 / Strings:**
- `remcosrat.com`, `rc4key=`, `clientid=`

---

### 🧬 Redline Stealer (Stealer)

**Behavior:**
- Steals browser info, autofills, crypto wallets.
- Often spread via cracked software or loaders.

**Behavior Path:**
- `malicious.zip → .exe → exfil HTTP POST`

**Spawned Processes:**
- `taskhostw.exe`, `cmd.exe`, `explorer.exe`

**Known C2 / Strings:**
- `discord.com/api`, `wallet.dat`, `POST /panel/gate.php`

---

### 🧬 Raccoon Stealer (Stealer)

**Behavior:**
- Steals from browsers, FTP, email, crypto wallets.
- Dropped via loaders, sometimes exploit kits.

**Behavior Path:**
- `loader.exe → dropper.dll → HTTP beacon`

**Spawned Processes:**
- `rundll32.exe`, `cmd.exe`, `svchost.exe`

**Known C2 / Strings:**
- `wallet`, `POST /gate.php`, `Mozilla/5.0`, `.top`

---

### 🧬 GuLoader (Loader)

**Behavior:**
- Shellcode loader that delivers payloads.
- Uses obfuscation and anti-VM.

**Behavior Path:**
- `VBScript → powershell.exe → shellcode stub`

**Spawned Processes:**
- `powershell.exe`, `rundll32.exe`, `taskkill.exe`

**Known C2 / Strings:**
- `VirtualAlloc`, `Shellcode=`, `AppData\\Temp`

---

### 🧬 LokiBot (Stealer)

**Behavior:**
- Targets credentials, FTP, web forms.
- Self-deletes after execution.

**Behavior Path:**
- `invoice.docm → loader.exe → config.ini parse`

**Spawned Processes:**
- `explorer.exe`, `cmd.exe`, `taskmgr.exe`

**Known C2 / Strings:**
- `config.ini`, `password=`, `cardnumber`, `ftp.host`

---

### 🧬 IcedID (Banking Trojan / Loader)

**Behavior:**
- DLL-based banking trojan.
- Delivers post-ex tools and Cobalt Strike.

**Behavior Path:**
- `.docm → DLL sideload → svchost.exe injection`

**Spawned Processes:**
- `rundll32.exe`, `explorer.exe`, `svchost.exe`

**Known C2 / Strings:**
- `inj_load`, `flintstorm.xyz`, `dpost.php`

---

### 🧬 Cobalt Strike (Post-Exploitation)

**Behavior:**
- Beacon framework used for C2 and lateral movement.
- Often injected into memory.

**Behavior Path:**
- `malicious.exe → beacon.dll (injected) → HTTP/DNS C2`

**Spawned Processes:**
- `powershell.exe`, `rundll32.exe`, `wmi.exe`

**Known C2 / Strings:**
- `artifact=`, `http-get`, `cdn.safezone.pw`, `dns-txt`

---

### 🧬 Adwind (Java RAT)

**Behavior:**
- Java-based RAT, multiplatform.
- Keylogging, file grab, webcam.

**Behavior Path:**
- `invoice.jar → Java.exe → RAT loop`

**Spawned Processes:**
- `javaw.exe`, `java.exe`

**Known C2 / Strings:**
- `javax.crypto`, `Runtime.exec`, `jrat`

---

### 🧬 Amadey (Stealer / Loader)

**Behavior:**
- Collects OS + software info.
- Common loader for SmokeLoader, Redline.

**Behavior Path:**
- `dropper.exe → beacon → plugin download`

**Spawned Processes:**
- `cmd.exe`, `powershell.exe`, `svchost.exe`

**Known C2 / Strings:**
- `panel.php`, `tasks`, `botnet_id`

---

### 🧬 Anarchy Stealer (Stealer)

**Behavior:**
- Steals Discord tokens, cookies, basic creds.
- Amateur-level stealer used in low-tier kits.

**Behavior Path:**
- `gamecrack.exe → .bat → txt dump`

**Spawned Processes:**
- `explorer.exe`, `cmd.exe`, `discord.exe`

**Known C2 / Strings:**
- `discord.com/api`, `user\\AppData`, `.txt dump`

---

### 🧬 Astaroth (LOLBins Loader / Stealer)

**Behavior:**
- Fileless malware using living-off-the-land tools.
- Grabs clipboard data, passwords.

**Behavior Path:**
- `.lnk → wmic.exe → regsvr32.exe → stealth module`

**Spawned Processes:**
- `regsvr32.exe`, `wmic.exe`, `certutil.exe`

**Known C2 / Strings:**
- `wmic`, `certutil`, `Invoke-Command`, `get-content`

---

### 🧬 AteraAgent (Remote Admin)

**Behavior:**
- Legitimate RMM used in malicious campaigns.
- Often dropped by loaders.

**Behavior Path:**
- `loader.exe → ateraagent.exe → beacon`

**Spawned Processes:**
- `ateraagent.exe`, `powershell.exe`, `cmd.exe`

**Known C2 / Strings:**
- `app.atera.com`, `rmm`, `monitoring`

---

### 🧬 Atlantida Stealer (Stealer)

**Behavior:**
- Browser stealer with simple exfil format.
- Credential targeting, silent dump.

**Behavior Path:**
- `fake_installer.exe → info grabber → C2 send`

**Spawned Processes:**
- `cmd.exe`, `explorer.exe`, `schtasks.exe`

**Known C2 / Strings:**
- `wallet.dat`, `outlook\\`, `autofill`

---

### 🧬 Aurora / BlackGuard (Stealer)

**Behavior:**
- .NET stealer used in subscription models.
- Discord, Telegram, wallets, cookies.

**Behavior Path:**
- `crack.exe → stub.dll → exfiltration`

**Spawned Processes:**
- `taskhostw.exe`, `rundll32.exe`

**Known C2 / Strings:**
- `.fun`, `data.json`, `discordapp.com`, `POST /panel`

---

### 🧬 Ave Maria (RAT)

**Behavior:**
- Remote access trojan with mic/cam grab.
- Used for initial access + persistence.

**Behavior Path:**
- `.xlsm → ave.exe → watchdog`

**Spawned Processes:**
- `ave.exe`, `cmd.exe`, `wscript.exe`

**Known C2 / Strings:**
- `RunPE`, `watchdog`, `connect.backdoor`

---

### 🧬 Azorult (Stealer)

**Behavior:**
- Infostealer for browser data, cookies, crypto.
- Older but still active in bundles.

**Behavior Path:**
- `.doc → dropper.exe → C2 beacon`

**Spawned Processes:**
- `cmd.exe`, `rundll32.exe`, `explorer.exe`

**Known C2 / Strings:**
- `wallet`, `telegram_id`, `autofill`, `cookies.sqlite`

---

### 🧬 Bandook (RAT)

**Behavior:**
- Remote access tool used by APTs.
- Captures screen, logs keystrokes, uploads files.
- Packed and obfuscated payloads.

**Behavior Path:**
- `dropper.exe → injected.dll → persistence service`

**Spawned Processes:**
- `svchost.exe`, `explorer.exe`, `cmd.exe`

**Known C2 / Strings:**
- `POST /gate.php`, `command=`, `BANDOOK`

---

### 🧬 Banload (Banking Trojan Downloader)

**Behavior:**
- Common LATAM banking malware loader.
- Drops payloads like Grandoreiro, BBTok.

**Behavior Path:**
- `phishing.pdf → banload.exe → drop banker`

**Spawned Processes:**
- `explorer.exe`, `powershell.exe`, `cmd.exe`

**Known C2 / Strings:**
- `.br`, `bb.banco`, `inject.js`, `bank_token`

---

### 🧬 BBTok Banking Trojan

**Behavior:**
- LATAM banking trojan with overlay injection.
- Voice-based phishing capability.

**Behavior Path:**
- `banload → bbtok.exe → browser overlay`

**Spawned Processes:**
- `bbtok.exe`, `explorer.exe`

**Known C2 / Strings:**
- `POST /api/token`, `banking_ui`, `caixa`

---

### 🧬 Bazar-Backdoor

**Behavior:**
- Backdoor associated with Conti operators.
- Delivered via IcedID or fake call scams.

**Behavior Path:**
- `Office macro → bazar.exe → post-ex tool`

**Spawned Processes:**
- `cmd.exe`, `powershell.exe`, `explorer.exe`

**Known C2 / Strings:**
- `api/v1/client`, `bazar`, `command_queue`, `beacon`

---

### 🧬 BitRAT (RAT)

**Behavior:**
- Full-featured C# RAT with remote shell, webcam access.
- Cracked/pirated versions circulate widely.

**Behavior Path:**
- `loader.exe → BitRAT.exe → persistence reg key`

**Spawned Processes:**
- `BitRAT.exe`, `cmd.exe`, `reg.exe`

**Known C2 / Strings:**
- `command_id`, `rclient`, `bitrat`, `POST /data`

---

### 🧬 Blackmoon (Banking Trojan)

**Behavior:**
- Korean banking trojan with browser injection.
- Targets login portals via phishing redirects.

**Behavior Path:**
- `browser hijack → proxy.exe → credential theft`

**Spawned Processes:**
- `iexplore.exe`, `chrome.exe`, `proxy.exe`

**Known C2 / Strings:**
- `bank.kr`, `naver.com`, `phishpage.html`

---

### 🧬 Blank Grabber (Stealer)

**Behavior:**
- Python-based stealer compiled into EXE.
- Dumps browser info, Discord tokens, crypto wallets.

**Behavior Path:**
- `EXE → txt output → C2 POST or Telegram`

**Spawned Processes:**
- `explorer.exe`, `cmd.exe`, `pythonw.exe`

**Known C2 / Strings:**
- `discord.com/api`, `autofill`, `.grabbed`, `login_data`

---

### 🧬 Bumblebee (Loader)

**Behavior:**
- Sophisticated loader used by several ransomware groups.
- Often replaces Bazar or IcedID.

**Behavior Path:**
- `.lnk → dll loader → CobaltStrike beacon`

**Spawned Processes:**
- `dllhost.exe`, `powershell.exe`, `wscript.exe`

**Known C2 / Strings:**
- `bumblebee_beacon`, `modules.json`, `loader_id=`

---

### 🧬 Byakugan (Stealer)

**Behavior:**
- Lightweight stealer, mostly for Discord tokens and creds.
- Delivered via fake game hacks or cracked tools.

**Behavior Path:**
- `keygen.exe → data dump → pastebin`

**Spawned Processes:**
- `explorer.exe`, `cmd.exe`, `chrome.exe`

**Known C2 / Strings:**
- `discord`, `autofill`, `pastebin`, `.grabber`

---

### 🧬 ConnectWise RAT (Commercial RAT Abuse)

**Behavior:**
- Legitimate RMM abused in IT support scams.
- Silent install, persistence via service.

**Behavior Path:**
- `installer.exe → cwagent.exe → system service`

**Spawned Processes:**
- `cwagent.exe`, `cmd.exe`, `taskhost.exe`

**Known C2 / Strings:**
- `connectwise.com`, `screenconnect`, `remoteagent`

---

### 🧬 Conti (Ransomware)

**Behavior:**
- Human-operated ransomware using Cobalt Strike.
- Encrypts local/network files, disables recovery.

**Behavior Path:**
- `Cobalt beacon → powershell → ransomware.exe`

**Spawned Processes:**
- `powershell.exe`, `taskkill.exe`, `ransomware.exe`

**Known C2 / Strings:**
- `.conti`, `shadowcopy`, `net use`, `volume shadow`

---

### 🧬 DarkGate (Loader / RAT)

**Behavior:**
- Loader with RAT and stealer capabilities.
- Distributed via malvertising and spam.

**Behavior Path:**
- `jsloader → AutoIT exe → payload`

**Spawned Processes:**
- `autoit3.exe`, `cmd.exe`, `schtasks.exe`

**Known C2 / Strings:**
- `gate.php`, `task_id`, `socks`, `AES_key`

---

### 🧬 ModiLoader / DBatLoader (Loader)

**Behavior:**
- Dropper family delivering stealers like Raccoon.
- Tends to use nested zip/iso > shortcut > JS chains.

**Behavior Path:**
- `.zip → .iso → .lnk → .js → payload`

**Spawned Processes:**
- `wscript.exe`, `cmd.exe`, `rundll32.exe`

**Known C2 / Strings:**
- `cmd.exe /c`, `schtasks`, `modi`, `drop.log`

---

### 🧬 DCRat (RAT)

**Behavior:**
- Russian-language custom RAT platform.
- Remote shell, screenshot, webcam, keylog.

**Behavior Path:**
- `dropper.exe → dcclient.exe → C2 loop`

**Spawned Processes:**
- `dcclient.exe`, `cmd.exe`, `rundll32.exe`

**Known C2 / Strings:**
- `cmdline=`, `botid=`, `post.php`, `task_id`

---

### 🧬 Dridex (Banking Trojan / Loader)

**Behavior:**
- One of the earliest modular banking trojans.
- Injects into Word or system processes.

**Behavior Path:**
- `macro.doc → Word.exe → explorer.exe injection`

**Spawned Processes:**
- `winword.exe`, `explorer.exe`, `taskhost.exe`

**Known C2 / Strings:**
- `xml_post`, `user_id`, `dridex_payload`, `POST /panel`

---

### 🧬 Expiro (Infostealer / Botnet Agent)

**Behavior:**
- Steals credentials, infects USB devices.
- Modular payloads and persistence.

**Behavior Path:**
- `exe packer → dll injection → beacon`

**Spawned Processes:**
- `explorer.exe`, `svchost.exe`, `cmd.exe`

**Known C2 / Strings:**
- `info.zip`, `ftp.`, `cmdkey`, `netstat`

---

### 🧬 FormBook (Stealer)

**Behavior:**
- Highly popular stealer-for-hire.
- Grabs credentials, screenshots, clipboard.

**Behavior Path:**
- `exe dropper → formbook.dll → beacon`

**Spawned Processes:**
- `explorer.exe`, `rundll32.exe`, `svchost.exe`

**Known C2 / Strings:**
- `panel/gate.php`, `data_id=`, `task=`, `fb_cookie`

---

### 🧬 Gh0st RAT (RAT)

**Behavior:**
- Classic Chinese RAT used for over a decade.
- GUI-based C2, full surveillance capability.

**Behavior Path:**
- `dropper.exe → gh0st.dll → persistence`

**Spawned Processes:**
- `svchost.exe`, `taskmgr.exe`, `cmd.exe`

**Known C2 / Strings:**
- `Gh0st`, `cmdline=`, `cmd.exe`, `POST /index.aspx`

---

### 🧬 Gooxion (Banking Trojan)

**Behavior:**
- Brazilian banking trojan.
- Uses overlays and fake pop-ups for credential theft.

**Behavior Path:**
- `pdf → gooxion.exe → overlay inject`

**Spawned Processes:**
- `chrome.exe`, `iexplore.exe`, `explorer.exe`

**Known C2 / Strings:**
- `.br`, `authcode`, `gov.br`, `netbanking`

---

### 🧬 GoTo RAT (RAT)

**Behavior:**
- Remote desktop abuse using legitimate GoToAssist tools.
- Often used in scam tech support incidents.

**Behavior Path:**
- `installer.exe → g2assist.exe → user remote control`

**Spawned Processes:**
- `g2assist.exe`, `cmd.exe`, `tasklist.exe`

**Known C2 / Strings:**
- `gotoassist.com`, `connect.goto.com`, `session_id=`

---

### 🧬 Grandoreiro (Banking Trojan)

**Behavior:**
- LATAM banking trojan with fake overlays.
- Written in Delphi, spread via malspam.

**Behavior Path:**
- `.zip → .msi → browser inject`

**Spawned Processes:**
- `msiexec.exe`, `cmd.exe`, `chrome.exe`

**Known C2 / Strings:**
- `.br`, `login=`, `token=`, `windows_update`

---

### 🧬 Horabot (Stealer / RAT)

**Behavior:**
- Multistage LATAM malware w/ RAT + credential theft.
- Delivered via PowerShell from phishing sites.

**Behavior Path:**
- `zip → powershell script → horabot.exe`

**Spawned Processes:**
- `powershell.exe`, `cmd.exe`, `schtasks.exe`

**Known C2 / Strings:**
- `cmd.exe /c`, `logininfo.dat`, `payload.ps1`

---

### 🧬 JanelaRAT (RAT)

**Behavior:**
- .NET-based RAT, mostly seen in South America.
- Offers remote shell, screen capture, file manager.

**Behavior Path:**
- `installer.exe → janela.exe → persistence reg key`

**Spawned Processes:**
- `janela.exe`, `cmd.exe`, `taskmgr.exe`

**Known C2 / Strings:**
- `janela_request`, `remote_shell`, `getinfo`

---

### 🧬 KLBanker (Banking Trojan)

**Behavior:**
- Trojan targeting Korean banks.
- Captures browser traffic, form data.

**Behavior Path:**
- `phish.doc → downloader → klbanker.dll`

**Spawned Processes:**
- `iexplore.exe`, `chrome.exe`, `taskmgr.exe`

**Known C2 / Strings:**
- `.kr`, `banking_id`, `klbanker`, `credentials=`

---

### 🧬 Kutaki (Stealer)

**Behavior:**
- Discord token & credential stealer.
- Simple batch + PowerShell-based grabber.

**Behavior Path:**
- `.bat → powershell → browser dump`

**Spawned Processes:**
- `powershell.exe`, `cmd.exe`, `explorer.exe`

**Known C2 / Strings:**
- `discord`, `tokens`, `cookies.sqlite`, `.grab`

---

### 🧬 Lampion (Banking Trojan)

**Behavior:**
- Portuguese-language banking malware.
- Drops VBS loaders and DLLs from public cloud.

**Behavior Path:**
- `pdf → vbs → DLL download → banker`

**Spawned Processes:**
- `wscript.exe`, `cmd.exe`, `rundll32.exe`

**Known C2 / Strings:**
- `onedrive.live.com`, `lampion.exe`, `POST /panel`

---

### 🧬 Loda RAT (RAT / InfoStealer)

**Behavior:**
- AutoIt-based RAT with stealer capabilities.
- Can interact with mouse/keyboard, webcam.

**Behavior Path:**
- `.vbs → loda.exe → persistence via reg key`

**Spawned Processes:**
- `autoit3.exe`, `loda.exe`, `powershell.exe`

**Known C2 / Strings:**
- `panel.php`, `task_id=`, `bot_id=`, `AutoIt`

---

### 🧬 Lumma Stealer (Stealer)

**Behavior:**
- Modern .NET-based infostealer.
- Exfiltrates to Telegram or custom HTTP C2s.

**Behavior Path:**
- `fake_installer.exe → lumma.exe → dump to zip`

**Spawned Processes:**
- `lumma.exe`, `explorer.exe`, `cmd.exe`

**Known C2 / Strings:**
- `telegram_api`, `wallet.dat`, `cookies.sqlite`

---

### 🧬 Mekotio / Metamorfo (Banking Trojan)

**Behavior:**
- LATAM trojan using overlays and clipboard mods.
- Delivered via MSI installers and fake updates.

**Behavior Path:**
- `.zip → .msi → .dll loader → trojan`

**Spawned Processes:**
- `msiexec.exe`, `explorer.exe`, `taskkill.exe`

**Known C2 / Strings:**
- `.br`, `getbalance`, `inject.html`, `windows_update`

---

### 🧬 MetaStealer (Stealer)

**Behavior:**
- Targets macOS, written in Go or C.
- Delivered as fake PDFs or zips.

**Behavior Path:**
- `app.pkg → metashell → keychain access`

**Spawned Processes:**
- `metastealer`, `osascript`, `launchctl`

**Known C2 / Strings:**
- `AppleID`, `keychain`, `wallet.dat`

---

### 🧬 Mispadu (Banking Trojan)

**Behavior:**
- Spam-delivered LATAM banker.
- Written in Delphi, manipulates browser UI.

**Behavior Path:**
- `.lnk → VBScript → Delphi trojan`

**Spawned Processes:**
- `wscript.exe`, `cmd.exe`, `explorer.exe`

**Known C2 / Strings:**
- `login_attempt`, `inject`, `auth_token`

---

### 🧬 ModernLoader (Loader / Bot)

**Behavior:**
- Loader for stealers, cryptominers, and RATs.
- Encrypted configs, uses PowerShell and .NET.

**Behavior Path:**
- `.docm → powershell → .NET loader`

**Spawned Processes:**
- `powershell.exe`, `regsvr32.exe`, `explorer.exe`

**Known C2 / Strings:**
- `bot_id=`, `hwid=`, `injector`, `POST /command`

---

### 🧬 Muck Stealer (Stealer)

**Behavior:**
- Discord-based stealer for passwords, tokens, cookies.
- Often packed with PyInstaller.

**Behavior Path:**
- `.exe → Chrome grabber → webhook dump`

**Spawned Processes:**
- `python.exe`, `cmd.exe`, `muck.exe`

**Known C2 / Strings:**
- `discord.com/api`, `grabbed.txt`, `token=`

---

### 🧬 Mystic (Stealer)

**Behavior:**
- Grabber that targets gaming, crypto, and browser data.
- Also screenshots and webcam capture.

**Behavior Path:**
- `.exe → mystic.exe → zipped output`

**Spawned Processes:**
- `mystic.exe`, `cmd.exe`, `tasklist.exe`

**Known C2 / Strings:**
- `webhook`, `cookies.sqlite`, `key3.db`

---

### 🧬 Nanocore (RAT)

**Behavior:**
- Long-running commodity RAT.
- Full remote control, file ops, keylogging.

**Behavior Path:**
- `loader.exe → nanocore.exe → install as service`

**Spawned Processes:**
- `nanocore.exe`, `cmd.exe`, `powershell.exe`

**Known C2 / Strings:**
- `nanoclient`, `rc4`, `panel`, `task_queue`

---

### 🧬 NetSupport Manager RAT

**Behavior:**
- Legitimate RMM used maliciously.
- Often silently installed for remote access.

**Behavior Path:**
- `vbscript → ns.exe → install service`

**Spawned Processes:**
- `client32.exe`, `cmd.exe`, `ns.exe`

**Known C2 / Strings:**
- `NetSupport`, `client32`, `remoteadmin`

---

### 🧬 NJRAT (RAT)

**Behavior:**
- Widely used .NET RAT.
- Offers file access, webcam, keylogger.

**Behavior Path:**
- `.exe → config parse → beacon`

**Spawned Processes:**
- `njrat.exe`, `explorer.exe`, `cmd.exe`

**Known C2 / Strings:**
- `njrat`, `cmdline=`, `task=`, `socket.connect`

---

### 🧬 OptiTune RAT

**Behavior:**
- Commercial RMM abused by threat actors.
- Similar abuse cases to Atera and AnyDesk.

**Behavior Path:**
- `installer → optitune.exe → autorun task`

**Spawned Processes:**
- `optitune.exe`, `cmd.exe`, `reg.exe`

**Known C2 / Strings:**
- `optitune`, `it.config`, `remoteview`

---

### 🧬 Ousaban (Banking Trojan)

**Behavior:**
- Brazilian banker with credential overlays.
- Anti-debug, keylogger, clipboard grabber.

**Behavior Path:**
- `shortcut → dropper → overlay injection`

**Spawned Processes:**
- `ousaban.exe`, `rundll32.exe`, `chrome.exe`

**Known C2 / Strings:**
- `overlay`, `wallet.dat`, `bancobr`, `inject.js`

---

### 🧬 Parallax RAT (RAT)

**Behavior:**
- Commodity RAT for keylogging, clipboard theft, webcam access.
- Delivered via malicious macros or phishing lures.

**Behavior Path:**
- `docm → vbs → parallax.exe`

**Spawned Processes:**
- `parallax.exe`, `wscript.exe`, `cmd.exe`

**Known C2 / Strings:**
- `parallaxrat`, `gate.php`, `task_id=`

---

### 🧬 Phoenix Stealer (Stealer)

**Behavior:**
- Modular stealer-as-a-service.
- Targets browser data, Telegram, Discord, FTP.

**Behavior Path:**
- `installer.exe → phoenix.exe → C2 zip dump`

**Spawned Processes:**
- `phoenix.exe`, `cmd.exe`, `powershell.exe`

**Known C2 / Strings:**
- `wallet.dat`, `discord.com/api`, `cookies.sqlite`

---

### 🧬 PureCrypter (Loader / Crypter)

**Behavior:**
- .NET crypter for obfuscation and delivery.
- Encrypts loaders for bypassing AV.

**Behavior Path:**
- `crypter.exe → payload loader → decrypted drop`

**Spawned Processes:**
- `payload.exe`, `explorer.exe`, `powershell.exe`

**Known C2 / Strings:**
- `purecrypter`, `stub=`, `POST /data`

---

### 🧬 QuasarRAT (RAT)

**Behavior:**
- .NET open-source RAT.
- Provides full control, keylogging, remote desktop.

**Behavior Path:**
- `quasar.exe → config.bin → C2 beacon`

**Spawned Processes:**
- `quasar.exe`, `cmd.exe`, `reg.exe`

**Known C2 / Strings:**
- `quasar`, `heartbeat=`, `tcp_connect`

---

### 🧬 R77Loader (Stealth Loader)

**Behavior:**
- Fileless loader with process hollowing.
- Known for stealthy persistence techniques.

**Behavior Path:**
- `cmd.exe → powershell → hollowed.exe`

**Spawned Processes:**
- `powershell.exe`, `svchost.exe`, `cmd.exe`

**Known C2 / Strings:**
- `r77shell`, `hook.dll`, `selfinject`

---

### 🧬 RATicate (Loader Campaign)

**Behavior:**
- Umbrella campaign with loaders like Valak, NetSupport.
- Lure documents → SFX → payload.

**Behavior Path:**
- `.docx → .sfx archive → .bat → payload.exe`

**Spawned Processes:**
- `sfx.exe`, `cmd.exe`, `payload.exe`

**Known C2 / Strings:**
- `raticate`, `launch.bat`, `pwsh.exe`

---

### 🧬 RisePro (Stealer)

**Behavior:**
- .NET stealer focused on Discord and cryptocurrency.
- Common on underground forums.

**Behavior Path:**
- `dropper → risepro.exe → POST to webhook`

**Spawned Processes:**
- `risepro.exe`, `taskhostw.exe`, `cmd.exe`

**Known C2 / Strings:**
- `discord.com`, `wallet.dat`, `autofill`

---

### 🧬 SnakeKeylogger (Stealer / Logger)

**Behavior:**
- Captures keystrokes, screenshots, clipboard.
- Exfil via SMTP or FTP.

**Behavior Path:**
- `.xlsb → dropper.exe → smtp beacon`

**Spawned Processes:**
- `taskmgr.exe`, `cmd.exe`, `smtpclient.exe`

**Known C2 / Strings:**
- `smtp.send`, `keylog=`, `credentials.txt`

---

### 🧬 SmokeLoader (Loader)

**Behavior:**
- Modular loader for stealers, RATs, banking malware.
- Frequently updates to avoid detection.

**Behavior Path:**
- `doc macro → payload.exe → plugin load`

**Spawned Processes:**
- `smoke.exe`, `explorer.exe`, `cmd.exe`

**Known C2 / Strings:**
- `plugin_id`, `botid=`, `gate.php`, `post.php`

---

### 🧬 Snake (Turla Rootkit)

**Behavior:**
- Complex cyber-espionage framework from Turla APT.
- Covert communication via compromised systems.

**Behavior Path:**
- `dropper → kernel driver → rootkit tunnel`

**Spawned Processes:**
- `csrss.exe`, `services.exe`, `wininit.exe`

**Known C2 / Strings:**
- `uaworker`, `pipe\\`, `snk_data`, `cmd_id=`

---

### 🧬 SocGholish (Loader Framework)

**Behavior:**
- JavaScript framework used for loading malware.
- Injects via compromised websites.

**Behavior Path:**
- `compromised_site.js → powershell → exe download`

**Spawned Processes:**
- `powershell.exe`, `wscript.exe`, `cmd.exe`

**Known C2 / Strings:**
- `panel.js`, `jQuery.payload`, `click.js`

---

### 🧬 SolarMarker (Backdoor / Loader)

**Behavior:**
- Search-engine poisoning campaign.
- Loads PowerShell-based .NET backdoors.

**Behavior Path:**
- `.pdf.lnk → powershell loader → .NET beacon`

**Spawned Processes:**
- `powershell.exe`, `rundll32.exe`, `solar.exe`

**Known C2 / Strings:**
- `solarmarker`, `seo_payload`, `cloud.doc`

---

### 🧬 Supreme Stealer

**Behavior:**
- Discord token & credential stealer.
- Delivered via cracked software on YouTube/Telegram.

**Behavior Path:**
- `.exe → dump to txt → Discord webhook`

**Spawned Processes:**
- `supreme.exe`, `cmd.exe`, `chrome.exe`

**Known C2 / Strings:**
- `discord.com`, `cookies.sqlite`, `login_data`

---

### 🧬 SystemBC (Proxy / Loader)

**Behavior:**
- Proxy malware used to hide C2 traffic.
- SOCKS5 tunnel or remote shell access.

**Behavior Path:**
- `dropper → systembc.exe → encrypted C2 tunnel`

**Spawned Processes:**
- `systembc.exe`, `svchost.exe`, `cmd.exe`

**Known C2 / Strings:**
- `socks5`, `relay=`, `enc_data=`

---

### 🧬 TA558 Loader

**Behavior:**
- Loader campaign targeting LATAM orgs.
- VBA macros + AutoIT + DLL loader chain.

**Behavior Path:**
- `.xlsm → AutoIT → rundll32.exe loader`

**Spawned Processes:**
- `autoit3.exe`, `rundll32.exe`, `cmd.exe`

**Known C2 / Strings:**
- `latam.dll`, `cmd.exe /c`, `ta558`

---

### 🧬 TA578 (Malware Campaign Tag)

**Behavior:**
- Refers to a cluster that distributes loaders like Bumblebee, AsyncRAT.
- Variable behavior depending on toolchain.

**Behavior Path:**
- `phish → loader → final payload (varies)`

**Spawned Processes:**
- Varies — usually `powershell`, `cmd`, `dllhost`

**Known C2 / Strings:**
- `campaign_id`, `client_token`, `task_payload`

---

### 🧬 Taurus Stealer (Stealer)

**Behavior:**
- Commercial stealer from same group behind PredatorTheThief.
- Browser, crypto, FTP, Telegram.

**Behavior Path:**
- `exe → dump credentials → C2 beacon`

**Spawned Processes:**
- `taurus.exe`, `taskhostw.exe`, `cmd.exe`

**Known C2 / Strings:**
- `telegram_id`, `wallet.dat`, `autofill=`

---

### 🧬 Vidar (Stealer)

**Behavior:**
- Browser, clipboard, file grabber.
- Commonly delivered via Fallout exploit kit or loaders.

**Behavior Path:**
- `.exe → beacon → .dat dump → exfil`

**Spawned Processes:**
- `vidar.exe`, `cmd.exe`, `svchost.exe`

**Known C2 / Strings:**
- `POST /gate.php`, `profile.dat`, `token=`

---

### 🧬 Warzone RAT

**Behavior:**
- Full-functionality RAT sold on forums.
- Webcam, file access, credential steal.

**Behavior Path:**
- `.docm → loader.exe → warzone.exe`

**Spawned Processes:**
- `warzone.exe`, `cmd.exe`, `powershell.exe`

**Known C2 / Strings:**
- `task_id`, `rc4`, `beacon=`, `rat.exe`

---

### 🧬 XWorm (RAT)

**Behavior:**
- .NET-based RAT with obfuscation and packer support.
- Logs keystrokes, manages files, DDoS modules.

**Behavior Path:**
- `stub.exe → decrypt payload → beacon`

**Spawned Processes:**
- `xworm.exe`, `rundll32.exe`, `cmd.exe`

**Known C2 / Strings:**
- `panel`, `keylogger=`, `pastebin`, `socket.connect`

---

### 🧬 YamaBot (Backdoor / APT Tool)

**Behavior:**
- Used by APT groups like BlackTech.
- Written in Go; allows remote shell, file management.

**Behavior Path:**
- `installer.exe → yamabot → periodic beacon`

**Spawned Processes:**
- `yamabot.exe`, `cmd.exe`, `powershell.exe`

**Known C2 / Strings:**
- `yamabot`, `task_id=`, `systeminfo`, `base64=`

---

### 🧬 ZLoader (Banking Trojan / Loader)

**Behavior:**
- Modular malware family used to load ransomware.
- Dropped via fake software installers or macro docs.

**Behavior Path:**
- `.docm → mshta.exe → zloader.dll`

**Spawned Processes:**
- `mshta.exe`, `rundll32.exe`, `cmd.exe`

**Known C2 / Strings:**
- `panel/gate.php`, `dlrun`, `zld_id=`, `formgrab`

---

### 🧬 Zeus Panda (Banking Trojan)

**Behavior:**
- Variant of Zeus banking malware.
- Uses injection and proxy configs to steal banking data.

**Behavior Path:**
- `.docx → powershell → payload injects into browser`

**Spawned Processes:**
- `powershell.exe`, `chrome.exe`, `iexplore.exe`

**Known C2 / Strings:**
- `zeus`, `cfg.dat`, `PANDA`, `formgrab`

---

### 🧬 ZeuS Sphinx (Banking Trojan)

**Behavior:**
- Zeus variant with web inject and credential theft.
- Heavily obfuscated, often with packers.

**Behavior Path:**
- `JS loader → DLL → browser inject`

**Spawned Processes:**
- `chrome.exe`, `dllhost.exe`, `taskhostw.exe`

**Known C2 / Strings:**
- `sphinx`, `command=`, `inject.js`, `gate.php`

---

### 🧬 ZeroLogs (Log Cleaner / Timestomper)

**Behavior:**
- Wipes event logs, manipulates timestamps.
- Used post-ex for defense evasion.

**Behavior Path:**
- `dropper.exe → zerologs.exe → system clean`

**Spawned Processes:**
- `zerologs.exe`, `wevtutil.exe`, `powershell.exe`

**Known C2 / Strings:**
- `Clear-EventLog`, `timestomp`, `wevtutil cl`

---
