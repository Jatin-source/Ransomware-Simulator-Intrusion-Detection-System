Ransomware Simulator & Intrusion Detection System (IDS)

A safe and educational ransomware simulation environment featuring real-time filesystem intrusion detection, secure file encryption, and a Tkinter-based recovery GUI.

📌 Overview

This project provides a controlled and fully safe ransomware demonstration that encrypts only a sandbox directory, along with a real-time Intrusion Detection System (IDS) that monitors filesystem activity, logs suspicious behavior, and sends alerts.

It is designed for:

Cybersecurity students

Educators

Demonstrations & workshops

File monitoring research

SOC / Blue-team training

🚀 Key Features
🔐 Ransomware Simulation

Encrypts files in a dedicated sandbox only

AES-based Fernet encryption

Generates a RANSOM_NOTE.txt

Launches a Tkinter GUI requesting the decryption key

Supports full restore using the correct key

🛡️ Intrusion Detection System

Monitors directory events using Watchdog

Detects rapid suspicious activity

Writes to detailed log files

Sends:

Desktop notifications

Email alerts via SMTP

🖥️ Tkinter Recovery GUI

Simple interface for entering the decryption key

Automatically triggers full sandbox file recovery


📂 Project Structure
Ransomware-Simulator-and-IDS/
 ├── config/              # Local-only keys & email creds (ignored in Git)
 ├── docs/                # Banner, screenshots, and documentation
 ├── gui/                 # Tkinter ransom window
 ├── monitor/             # IDS filesystem monitor
 ├── sandbox/             # Target directory for simulation
 ├── sandbox_backup/      # Backup of clean files
 ├── simulator/           # Encryption & decryption engine
 ├── requirements.txt
 ├── .gitignore
 └── README.md

⚙️ Installation
1. Clone the repo
git clone https://github.com/<your-username>/Ransomware-Simulator-and-IDS.git
cd Ransomware-Simulator-and-IDS

2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

4. Install Tkinter (Linux only)
sudo apt install python3-tk

🔧 Configuration (MANDATORY)

Before running the IDS or simulator, create:

config/

Create config/creds.json
{
  "smtp": "smtp.gmail.com",
  "port": 587,
  "user": "your.email@gmail.com",
  "pass": "your_app_password",
  "to": "recipient@example.com"
}


Note:

Use Gmail App Password (not your real password).

This file is ignored through .gitignore for security.

Key File

key.bin will be auto-generated inside the config/ folder on first encryption.

▶️ Usage
Start IDS (Real-time Monitoring)
source venv/bin/activate
python3 monitor/fs_monitor.py

Run Ransomware Simulation
python3 simulator/safe_simulator.py --encrypt


This will:

Encrypt all files in sandbox/

Create ransom note

Launch GUI asking for the key

Decrypt Files (Restore)
python3 simulator/safe_simulator.py --decrypt


You can also decrypt using the GUI.

📜 Log Files

monitor/events.log – Raw filesystem events

monitor/alerts.log – IDS warnings & alerts

🧠 Important Notes

This is only a simulation.

Files outside sandbox/ are never touched.

Recommended to run inside a VM (Virtual Machine).

Perfect for a college cybersecurity project.

📄 License

This project is licensed under the MIT License, allowing free modification and usage while disclaiming liability.

⭐ Support

If you found this project useful, please give it a ⭐ on GitHub!