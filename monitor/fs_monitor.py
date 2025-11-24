#!/usr/bin/env python3
"""
Improved fs_monitor:
- Prevents false alerts (txt/md editing won't trigger)
- Detects ONLY ransomware-like behavior:
    • .locked file creation
    • rapid mass changes within seconds
    • deletion of originals
- Stable desktop notifications added
- Email + logging behavior unchanged
"""

import time, logging, subprocess, smtplib, json, requests
from collections import deque
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# CONFIG PATHS (unchanged)
SANDBOX = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/sandbox")
ALERT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/alerts.log")
EVENT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/events.log")
CONFIG_CREDS = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/config/creds.json")
STOP_FILE = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/STOP_ALL")

EVENT_WINDOW = 2.5
EVENT_THRESHOLD = 3
ALERT_COOLDOWN = 8

SAFE_EDIT_EXT = {".txt", ".md", ".json", ".py", ".cfg", ".jpg", ".jpeg", ".png"}

NOTIFY_TITLE = "Security Alert — Suspicious Activity"
NOTIFY_BODY_SHORT = "The IDS detected unusual file changes in the sandbox."
EMAIL_SUBJECT_PREFIX = "IDS Alert"

EMAIL_BODY_HEADER = """Hello,

Your demo IDS detected suspicious activity in the sandbox. Below are the details:
"""

timestamps = deque()
recent_events = deque(maxlen=80)
last_alert_time = 0

EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=str(EVENT_LOG), level=logging.INFO,
                    format="%(asctime)s %(message)s")


# =====================================================
# STABLE DESKTOP NOTIFICATION WRAPPER
# =====================================================
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
        logging.warning("notify-send not installed")

    except Exception as e:
        logging.warning("Notification failed: %s", e)


# =====================================================
# EMAIL SENDER (Mailjet API)
# =====================================================
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
                    "HTMLPart": body_html or f"<pre>{body_text}</pre>"
                }
            ]
        }

        response = requests.post(
            "https://api.mailjet.com/v3.1/send",
            auth=(api_key, secret_key),
            json=payload,
            timeout=10
        )

        if response.status_code in (200, 201):
            logging.info("Mailjet: Email sent successfully")
        else:
            logging.error("Mailjet error: %s %s", response.status_code, response.text)

    except Exception as e:
        logging.exception("Mailjet send_email() error: %s", e)


# =====================================================
# ALERT GENERATOR
# =====================================================
def send_alert(detail_message, sample_paths):
    global last_alert_time
    now = time.time()

    if now - last_alert_time < ALERT_COOLDOWN:
        return

    last_alert_time = now

    # Reliable desktop popup
    desktop_notify(NOTIFY_TITLE, NOTIFY_BODY_SHORT)

    with open(ALERT_LOG, "a") as f:
        f.write(f"{datetime.now()} ALERT: {detail_message}\n")

    sample_text = "\n".join(f"- {p}" for p in sample_paths) or "(no files)"

    body_text = (
        EMAIL_BODY_HEADER +
        f"\nTime: {datetime.now()}\n"
        f"Sandbox: {SANDBOX}\n"
        f"Details: {detail_message}\n\n"
        f"Files:\n{sample_text}\n"
        "\n(This is just a demo IDS)"
    )

    send_email(f"{EMAIL_SUBJECT_PREFIX}: Activity Detected", body_text, None)


# =====================================================
# MAIN FILE SYSTEM WATCHER LOGIC
# =====================================================
class MyHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        try:
            if STOP_FILE.exists():
                raise SystemExit()

            p = Path(event.src_path)
            now = time.time()

            # Ignore harmless edits
            if event.event_type == "modified" and p.suffix.lower() in SAFE_EDIT_EXT:
                return

            # SUSPICIOUS BEHAVIOR DETECTION
            is_suspicious = False

            if p.name.endswith(".locked"):
                is_suspicious = True
                timestamps.append(now)

            elif event.event_type == "deleted":
                is_suspicious = True
                timestamps.append(now)

            elif event.event_type in ("created", "modified", "moved"):
                timestamps.append(now)

            # Track events
            recent_events.append((now, event.event_type, str(p)))

            # Sliding window cleanup
            while timestamps and now - timestamps[0] > EVENT_WINDOW:
                timestamps.popleft()

            # Trigger alert if ransomware pattern detected
            if is_suspicious and len(timestamps) >= EVENT_THRESHOLD:
                sample = [e[2] for e in list(recent_events)[-10:]]

                send_alert(
                    f"{len(timestamps)} suspicious events detected in {EVENT_WINDOW}s",
                    sample
                )

                timestamps.clear()
                recent_events.clear()

        except Exception:
            logging.exception("Handler error")


# =====================================================
# MAIN LOOP
# =====================================================
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
    except KeyboardInterrupt:
        observer.stop()
    observer.join()