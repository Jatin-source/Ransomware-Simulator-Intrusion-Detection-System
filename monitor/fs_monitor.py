#!/usr/bin/env python3
"""
Friendly fs_monitor: sends friendly desktop + email alerts with useful details.
- Includes cooldown to avoid email spam.
- Gathers a small sample of changed file paths to include in the email.
"""
import time, logging, subprocess, smtplib, json
from collections import deque
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# CONFIG — change if needed
SANDBOX = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/sandbox")
ALERT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/alerts.log")
EVENT_LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/events.log")
CONFIG_CREDS = Path("/home/jatin/.config/Ransomware-Simulator-and-IDS/creds.json")
STOP_FILE = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/STOP_ALL")

EVENT_WINDOW = 3.0      # seconds to observe
EVENT_THRESHOLD = 2      # threshold to trigger alert
ALERT_COOLDOWN = 10     # seconds between emails (throttle)

# friendly templates
NOTIFY_TITLE = "Security alert — Action required (demo)"
NOTIFY_BODY_SHORT = "We detected unusual activity in your demo folder. Open the demo GUI."
EMAIL_SUBJECT_PREFIX = "Demo Alert"
EMAIL_BODY_HEADER = """Hello,

Our demo monitor detected unusual activity in the demo folder. This is an automated message from your local demo monitor. Below are the details.
"""

# internal state
timestamps = deque()
recent_events = deque(maxlen=100)  # store (ts, event_type, path)
last_alert_time = 0

EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=str(EVENT_LOG), level=logging.INFO, format="%(asctime)s %(message)s")

# ---------- Email sender ----------
def send_email(subject, body_text, body_html=None):
    """Send email using creds.json. body_html optional."""
    if not CONFIG_CREDS.exists():
        logging.info("No creds.json found; skipping email")
        return
    try:
        creds = json.loads(CONFIG_CREDS.read_text())
        smtp_server = creds.get("smtp")
        port = creds.get("port", 587)
        user = creds.get("user")
        passwd = creds.get("pass")
        toaddr = creds.get("to") or user
        if not (smtp_server and user and passwd):
            logging.warning("Incomplete SMTP creds; skipping email")
            return

        msg = MIMEMultipart("alternative")
        msg["From"] = user
        msg["To"] = toaddr
        msg["Subject"] = subject
        part1 = MIMEText(body_text, "plain")
        msg.attach(part1)
        if body_html:
            part2 = MIMEText(body_html, "html")
            msg.attach(part2)

        server = smtplib.SMTP(smtp_server, port, timeout=10)
        server.ehlo()
        server.starttls()
        server.login(user, passwd)
        server.sendmail(user, [toaddr], msg.as_string())
        server.quit()
        logging.info("Email sent to %s", toaddr)
    except Exception as e:
        logging.exception("Failed to send email: %s", e)

# ---------- Friendly alert function ----------
def send_alert(detail_message, sample_paths):
    global last_alert_time
    now_ts = time.time()
    # cooldown check
    if now_ts - last_alert_time < ALERT_COOLDOWN:
        logging.info("Alert suppressed due to cooldown (%.1fs remaining)", ALERT_COOLDOWN - (now_ts - last_alert_time))
        return
    last_alert_time = now_ts

    short_notify = NOTIFY_BODY_SHORT
    # desktop notify (short)
    try:
        subprocess.run(["notify-send", NOTIFY_TITLE, short_notify], check=False)
    except Exception:
        logging.exception("notify-send failed")

    # Write to local alert log
    try:
        with open(ALERT_LOG, "a", buffering=1) as f:  # line-buffered
            line = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " ALERT: " + detail_message + "\n"
            f.write(line)
            f.flush()  # force write immediately
    except Exception:
        logging.exception("Failed to write alert log")

    # Build friendly email body
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sample_text = "\n".join(f"- {p}" for p in sample_paths) if sample_paths else "No sample paths available."
    body_text = (
        EMAIL_BODY_HEADER +
        f"Time: {ts}\n"
        f"Demo folder: {SANDBOX}\n\n"
        f"Summary: {detail_message}\n\n"
        f"Example affected files (up to {len(sample_paths)} shown):\n{sample_text}\n\n"
        "What to do (demo):\n"
        "1) If you see the demo ransom GUI, enter the demo key to restore files.\n"
        "2) If you do not have the key, revert the VM snapshot 'before-sim-run'.\n"
        "3) This is a demo — take no real-world action on your host machine.\n\n"
        "If this were a real event, you would disconnect from network, preserve evidence, and contact a security professional.\n\n"
        "— Demo monitor"
    )

    # optional simple HTML version
    body_html = f"""
    <html><body>
    <p>{EMAIL_BODY_HEADER.replace('\n','<br>')}</p>
    <p><strong>Time:</strong> {ts}<br>
    <strong>Demo folder:</strong> {SANDBOX}</p>
    <p><strong>Summary:</strong> {detail_message}</p>
    <p><strong>Example files:</strong><br>{'<br>'.join(sample_paths if sample_paths else ['(none)'])}</p>
    <p><strong>What to do (demo):</strong><br>
    1) Open the demo GUI and enter the key.<br>
    2) If you don't have the key, restore the VM snapshot called 'before-sim-run'.<br>
    3) This is a demo — do not act on your host system.</p>
    <p>— Demo monitor</p>
    </body></html>
    """

    # send email
    subject = f"{EMAIL_SUBJECT_PREFIX}: Suspicious activity in demo folder"
    send_email(subject, body_text, body_html=body_html)
    logging.info("Alert email composed and sent (if creds present).")

# ---------- FS event handler ----------
class MyHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        try:
            if STOP_FILE.exists():
                logging.info("STOP_ALL present; monitor exiting."); raise SystemExit()
            # normalize path
            p = Path(event.src_path)
            if "quarantine" in str(p) or p.name.endswith((".tmp", ".locked")):
                return
            if event.event_type in ("created", "modified", "moved"):
                print(f"[DEBUG] Event: {event.event_type} -> {event.src_path}")
                logging.info(f"[DEBUG] Event: {event.event_type} -> {event.src_path}")
                
                now = time.time()
                timestamps.append(now)
                recent_events.append((now, event.event_type, str(p)))
                while timestamps and now - timestamps[0] > EVENT_WINDOW:
                    timestamps.popleft()
                if len(timestamps) >= EVENT_THRESHOLD:
                    # collect up to 10 sample file paths (most recent)
                    sample_paths = [e[2] for e in list(recent_events)[-10:]]
                    detail = f"{len(timestamps)} events in last {EVENT_WINDOW:.1f}s"
                    print(f"[DEBUG] Triggering alert: {detail}")
                    logging.info("Raising alert: %s ; samples: %s", detail, sample_paths)
                    send_alert(detail, sample_paths)
                    timestamps.clear()
                    recent_events.clear()
        except Exception:
            logging.exception("Error in event handler")

# ---------- main ----------
if __name__ == "__main__":
    if not SANDBOX.exists():
        print("Sandbox missing:", SANDBOX); exit(1)
    print("Monitor started. Watching:", SANDBOX)
    observer = Observer()
    handler = MyHandler()
    observer.schedule(handler, str(SANDBOX), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
            if STOP_FILE.exists():
                print("STOP_ALL found; stopping monitor.")
                break
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
