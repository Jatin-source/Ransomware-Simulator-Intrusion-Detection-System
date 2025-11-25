#!/usr/bin/env python3
import time
import os
import logging
import subprocess
import json
import requests
from collections import deque
from datetime import datetime
from pathlib import Path
from stat import S_IMODE

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# CONFIG PATHS

SANDBOX = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/sandbox")
ALERT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/alerts.log")
EVENT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/events.log")
CONFIG_CREDS = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/config/creds.json")
STOP_FILE = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/STOP_ALL")


# DETECTION TUNING (aggressive)

EVENT_WINDOW = 2.5          # generic burst window (seconds)
EVENT_THRESHOLD = 3         # events in window to consider "burst"
ALERT_COOLDOWN = 8          # seconds between alerts

# Bulk rename (extension changes)
BULK_RENAME_WINDOW = 5.0    # seconds
BULK_RENAME_THRESHOLD = 6   # number of ext-changes to alert

# Mass file creation
MASS_CREATE_WINDOW = 5.0    # seconds
MASS_CREATE_THRESHOLD = 10  # new files in window

# Permission anomalies
PERM_ZERO_ALERT = True      # chmod 000
PERM_EXEC_GAIN_ALERT = True # files suddenly becoming executable

# Safe edits (ignored modifications)
SAFE_EDIT_EXT = {
    ".txt", ".md", ".json", ".py", ".cfg",
    ".jpg", ".jpeg", ".png", ".gif", ".log"
}

# Suspicious extensions (often malware or scripts)
SUSPICIOUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".jse",
    ".jar", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".com", ".dll", ".sys", ".sh", ".run", ".msi"
}

# Common ransom-note filenames
RANSOM_NOTE_NAMES = {
    "RANSOM_NOTE.txt",
    "README_FOR_DECRYPT.txt",
    "DECRYPT_INSTRUCTIONS.txt",
    "HOW_TO_DECRYPT.txt"
}

# Notifications / email
NOTIFY_TITLE = "Security Alert — Suspicious Activity"
NOTIFY_BODY_SHORT = "The IDS detected unusual file changes in the sandbox."
EMAIL_SUBJECT_PREFIX = "IDS Alert"

EMAIL_BODY_HEADER = """Hello,

IDS has detected suspicious activity in the sandbox. Below are the details:
"""

# INTERNAL STATE

timestamps = deque()               # for generic bursts
recent_events = deque(maxlen=300)  # (ts, event_type, path)
last_alert_time = 0

# for rename & permission detection
_prev_suffix = {}                  # path -> last known suffix
_prev_mode = {}                    # path -> last known mode (int)

# for bulk rename and mass create
ext_change_times = deque()         # timestamps of extension changes
mass_create_times = deque()        # timestamps of created files

# Logging setup
EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(EVENT_LOG),
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# HELPER: Desktop notification
def desktop_notify(title, message):
    """Reliable notify-send wrapper with error logging."""
    try:
        result = subprocess.run(
            ["notify-send", title, message],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            logging.warning("notify-send error: %s", result.stderr.decode())
    except FileNotFoundError:
        logging.debug("notify-send not installed")
    except Exception as e:
        logging.warning("Notification failed: %s", e)

# HELPER: Email via Mailjet
def send_email(subject, body_text, body_html=None):
    """Send email through Mailjet REST API."""
    if not CONFIG_CREDS.exists():
        logging.info("No creds.json found — skipping email")
        return

    try:
        creds = json.loads(CONFIG_CREDS.read_text())
        if creds.get("service") != "mailjet":
            logging.warning("creds.json not configured for Mailjet")
            return

        api_key = creds.get("api_key")
        secret_key = creds.get("secret_key")
        from_email = creds.get("from_email")
        to_email = creds.get("to", from_email)

        payload = {
            "Messages": [
                {
                    "From": {"Email": from_email, "Name": "IDS Monitor"},
                    "To": [{"Email": to_email}],
                    "Subject": subject,
                    "TextPart": body_text,
                    "HTMLPart": body_html or f"<pre>{body_text}</pre>",
                }
            ]
        }

        response = requests.post(
            "https://api.mailjet.com/v3.1/send",
            auth=(api_key, secret_key),
            json=payload,
            timeout=10,
        )

        if response.status_code in (200, 201):
            logging.info("Mailjet: Email sent successfully")
        else:
            logging.error("Mailjet error: %s %s", response.status_code, response.text)

    except Exception as e:
        logging.exception("Mailjet send_email() error: %s", e)



# ALERT GENERATOR (detailed)
def send_alert(short_reason: str, explanation: str, sample_paths):
    """
    short_reason  -> brief title of what triggered
    explanation   -> multi-line explanation text
    sample_paths  -> list of file paths to include
    """
    global last_alert_time
    now = time.time()

    if now - last_alert_time < ALERT_COOLDOWN:
        logging.info("Alert suppressed due to cooldown")
        return

    last_alert_time = now

    # Desktop popup
    desktop_notify(NOTIFY_TITLE, NOTIFY_BODY_SHORT)

    # Log alert summary
    with open(ALERT_LOG, "a") as f:
        f.write(f"{datetime.now()} ALERT: {short_reason}\n")

    sample_text = "\n".join(f"- {p}" for p in sample_paths) or "(no files listed)"

    body_text = (
        EMAIL_BODY_HEADER
        + f"\nTime: {datetime.now()}\n"
        + f"Sandbox: {SANDBOX}\n"
        + f"Alert type: {short_reason}\n\n"
        + "What the IDS saw:\n"
        + explanation.strip()
        + "\n\nSample files involved:\n"
        + sample_text
        + "\n\n(PLEASE CHECK YOUR SANDBOX IMMEDIATELY!)"
    )

    send_email(f"{EMAIL_SUBJECT_PREFIX}: {short_reason}", body_text, None)
    logging.info("Alert sent: %s", short_reason)

# MAIN FILE SYSTEM WATCHER LOGIC

class MyHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        try:
            if STOP_FILE.exists():
                raise SystemExit()

            p = Path(event.src_path)
            now = time.time()

            # Only care about things inside sandbox
            try:
                if SANDBOX not in p.resolve().parents and p.resolve() != SANDBOX:
                    return
            except Exception:
                # If resolution fails, be safe and continue
                pass

            # Ignore harmless edits
            if event.event_type == "modified" and p.suffix.lower() in SAFE_EDIT_EXT:
                return

            # Track events
            recent_events.append((now, event.event_type, str(p)))
            timestamps.append(now)

            # Sliding window cleanup for generic burst
            while timestamps and now - timestamps[0] > EVENT_WINDOW:
                timestamps.popleft()

         
            # 1) RANSOM NOTE DETECTION
          
            if event.event_type in ("created", "modified") and p.name in RANSOM_NOTE_NAMES:
                explanation = (
                    f"A known ransom note filename was created or modified: {p.name}\n"
                    "- Ransomware often drops a note after encrypting files.\n"
                    "- Check the sandbox contents for encrypted (*.locked) files.\n"
                )
                send_alert("Ransom note detected", explanation, [str(p)])

         
            # 2) MASS FILE CREATION DETECTION
           
            if event.event_type == "created" and p.is_file():
                mass_create_times.append(now)
                # purge old timestamps
                while mass_create_times and now - mass_create_times[0] > MASS_CREATE_WINDOW:
                    mass_create_times.popleft()

                if len(mass_create_times) >= MASS_CREATE_THRESHOLD:
                    sample = [e[2] for e in recent_events if e[1] == "created"][-10:]
                    explanation = (
                        f"{len(mass_create_times)} files were created within "
                        f"{MASS_CREATE_WINDOW} seconds.\n"
                        "- Malware and ransomware often create many files quickly\n"
                        "  (temporary payloads, encrypted copies, logs, etc.).\n"
                        "- Verify that this burst of file creation is expected (e.g. bulk copy).\n"
                    )
                    send_alert("Mass file creation burst", explanation, sample)
                    mass_create_times.clear()

    
            # 3) PERMISSION ANOMALY DETECTION
           
            try:
                if p.exists() and p.is_file():
                    cur_mode = S_IMODE(p.stat().st_mode)
                    prev_mode = _prev_mode.get(str(p))
                    _prev_mode[str(p)] = cur_mode

                    if prev_mode is not None:
                        # chmod 000 (file becomes unreadable)
                        if PERM_ZERO_ALERT and prev_mode != 0 and cur_mode == 0:
                            explanation = (
                                f"File permissions changed to 000 on: {p}\n"
                                "- This makes the file unreadable and unwritable.\n"
                                "- Malware sometimes uses this to hide or lock files.\n"
                            )
                            send_alert("Permission anomaly: chmod 000", explanation, [str(p)])

                        # gained execute bit
                        prev_exec = bool(prev_mode & 0o111)
                        cur_exec = bool(cur_mode & 0o111)
                        if PERM_EXEC_GAIN_ALERT and not prev_exec and cur_exec:
                            explanation = (
                                f"File suddenly became executable: {p}\n"
                                "- Normal documents rarely gain execute permissions.\n"
                                "- This may indicate a script or binary being prepared to run.\n"
                            )
                            send_alert("Permission anomaly: exec bit gained", explanation, [str(p)])
            except Exception:
                logging.debug("Permission check failed for %s", p)

            
            # 4) BULK RENAME / EXTENSION STORM
           
            key = str(p)
            prev_suf = _prev_suffix.get(key)
            cur_suf = p.suffix.lower()
            if prev_suf is None:
                _prev_suffix[key] = cur_suf
            else:
                if prev_suf != cur_suf:
                    # extension changed
                    ext_change_times.append(now)
                    while ext_change_times and now - ext_change_times[0] > BULK_RENAME_WINDOW:
                        ext_change_times.popleft()
                    _prev_suffix[key] = cur_suf

                    if len(ext_change_times) >= BULK_RENAME_THRESHOLD:
                        sample = [e[2] for e in list(recent_events)[-20:]]
                        explanation = (
                            f"{len(ext_change_times)} files had their extensions changed within "
                            f"{BULK_RENAME_WINDOW} seconds.\n"
                            "- Ransomware rapidly renames files to add a new extension for\n"
                            "  encrypted data (e.g. .locked, .encrypted, .payme).\n"
                            "- If you did not intentionally bulk-rename files, treat this as suspicious.\n"
                        )
                        send_alert("Bulk rename / extension storm", explanation, sample)
                        ext_change_times.clear()

        
            # 5) SUSPICIOUS EXTENSION CREATION
            
            if event.event_type in ("created", "moved"):
                ext = p.suffix.lower()
                if ext in SUSPICIOUS_EXT:
                    explanation = (
                        f"A file with a high-risk extension was created or moved: {p}\n"
                        f"- Extension {ext} is commonly used for executables or scripts.\n"
                        "- If this file is not expected (installer, legitimate tool), it may be malware.\n"
                    )
                    send_alert("Suspicious executable/script file", explanation, [str(p)])

            # 6) CORE RANSOMWARE PATTERN (.locked / deletions)
           
            is_suspicious = False

            if p.name.endswith(".locked"):
                is_suspicious = True
            elif event.event_type == "deleted":
                is_suspicious = True

            # Generic burst: enough suspicious timestamps in window
            if is_suspicious and len(timestamps) >= EVENT_THRESHOLD:
                sample = [e[2] for e in list(recent_events)[-15:]]
                explanation = (
                    f"Detected {len(timestamps)} suspicious events ('.locked' files or deletions)\n"
                    f"within approximately {EVENT_WINDOW} seconds.\n"
                    "- Ransomware typically encrypts a batch of files and may delete originals.\n"
                    "- Check the sandbox for newly created *.locked files and missing documents.\n"
                )
                send_alert("Ransomware-like burst (.locked / deletions)", explanation, sample)
                timestamps.clear()
                recent_events.clear()

        except Exception:
            logging.exception("Handler error")
            

# MAIN LOOP
if __name__ == "__main__":
    if not SANDBOX.exists():
        print("Sandbox missing:", SANDBOX)
        exit(1)

    print("Monitor active — watching sandbox:", SANDBOX)

    observer = Observer()
    handler = MyHandler()
    observer.schedule(handler, str(SANDBOX), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
            if STOP_FILE.exists():
                print("STOP_ALL found — stopping monitor.")
                break
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
