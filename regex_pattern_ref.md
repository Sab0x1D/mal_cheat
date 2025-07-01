
# 🧪 Regex Pattern Reference (Malware Artifact Detection)

| 🔤 Regex Pattern                                              | 🔍 Matches / Description                     | 💀 Likely Families                          |
|--------------------------------------------------------------|----------------------------------------------|---------------------------------------------|
| `token=.*?(&|$)`                                             | Discord tokens, webhook stealers             | Various stealer families                    |
| `panel.php\ngate.php\nsubmit.php`                          | C2 PHP panel endpoints                       | FormBook, RedLine, Vidar, AsyncRAT          |
| `(smtp\|ftp)\.(yandex\|mail)`                             | Email-based exfil (SMTP/FTP)                 | Agent Tesla, SnakeKeylogger, LokiBot        |
| `task_id=|bot_id=`                                           | Loader task assignment / C2 parameters       | Loda RAT, TA558, DarkGate                   |
| `(cookies\|logins\|wallet)\.(sqlite\|json)`              | Browser data stealers (cookies, wallets)     | Vidar, Lumma, Taurus                        |
| `raw\.githubusercontent\.com/.+?\.ps1`                    | Remote PowerShell payload                    | AsyncRAT, TA578, Amadey                     |
| `discord(app)?\.com/api/webhooks`                          | Discord webhook exfil                        | Mystic, Anarchy, Blank Grabber              |
| `telegram\.(me\|org)/.+`                                   | Telegram bot exfiltration                    | Lumma, Raccoon, RedLine                     |
| `config\.ini`                                               | Config file used by stealers/loaders         | LokiBot, Remcos                             |
| `(grabbed\|creds\|dump)\.(txt\|zip)`                     | Local loot dump artifacts                    | Muck, Mystic, RisePro, Taurus               |
