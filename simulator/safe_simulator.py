#!/usr/bin/env python3
"""
safe_simulator.py - Direct file encryption/decryption demo
- Encrypts files in place (*.locked replaces original)
- Uses Fernet symmetric encryption
- --encrypt to lock files
- --decrypt to restore from .locked files
- Restores from both sandbox AND quarantine
"""
import argparse, sys, logging, subprocess, shutil
from pathlib import Path
from cryptography.fernet import Fernet

# --- Paths (use exact absolute paths for safety)
SANDBOX = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/sandbox")
QUARANTINE_DIR = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/quarantine")
CONFIG_DIR = Path("/home/jatin/.config/Ransomware-Simulator-and-IDS")
KEY_PATH = CONFIG_DIR / "key.bin"
STOP_FILE = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/STOP_ALL")
LOG = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/monitor/events.log")
RESTORE_FLAG = SANDBOX / ".restore_mode"
LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=str(LOG), level=logging.INFO, format="%(asctime)s %(message)s")

def ensure_key():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        key = Fernet.generate_key()
        KEY_PATH.write_bytes(key)
        KEY_PATH.chmod(0o600)
        print("Generated key at", KEY_PATH)
    return Fernet(KEY_PATH.read_bytes())

def safe_write(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)

def encrypt_file(path: Path, f: Fernet, dry_run=False):
    """Encrypt single file in place"""
    try:
        data = path.read_bytes()
        token = f.encrypt(data)
        locked_path = path.with_suffix(path.suffix + ".locked")
        if not dry_run:
            safe_write(locked_path, token)
            path.unlink()  # Remove original after successful encryption
        logging.info(f"Encrypted: {path} -> {locked_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to encrypt {path}: {e}")
        return False

def decrypt_file(path: Path, f: Fernet, dry_run=False):
    """Decrypt single locked file"""
    try:
        token = path.read_bytes()
        data = f.decrypt(token)
        orig_path = path.with_suffix(path.suffix.replace(".locked", ""))
        if not dry_run:
            safe_write(orig_path, data)
            path.unlink()  # Remove .locked file after successful decryption
        logging.info(f"Decrypted: {path} -> {orig_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to decrypt {path}: {e}")
        return False

def simulate_attack(dry_run=False):
    if STOP_FILE.exists():
        print("STOP_ALL present — aborting.")
        return
    f = ensure_key()
    files_encrypted = 0
    
    for p in sorted(SANDBOX.rglob("*")):
        if p.is_file() and not p.name.endswith((".locked", "RANSOM_NOTE.txt")):
            if encrypt_file(p, f, dry_run):
                files_encrypted += 1
                print(f"Encrypted: {p}")

    if files_encrypted == 0:
        print("No files to encrypt in sandbox.")
        return

    if not dry_run:
        note = SANDBOX / "RANSOM_NOTE.txt"
        note.write_text("Files encrypted! Run with --decrypt to restore.")
        BASE = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS")
        gui_script = BASE / "gui/ransom_gui.py"
        venv_python = BASE / "venv/bin/python"

        if gui_script.exists():
            subprocess.Popen([str(venv_python), str(gui_script)])
        else:
            print("GUI script not found:", gui_script)
    
    print(f"Encrypted {files_encrypted} files (dry_run={dry_run})")

def restore_files(dry_run=False):
    if STOP_FILE.exists():
        print("STOP_ALL present — aborting.")
        return
    
    # enable restore mode
    RESTORE_FLAG.touch()
    
    f = ensure_key()
    files_decrypted = 0

    # Restore from sandbox
    for p in sorted(SANDBOX.rglob("*.locked")):
        if decrypt_file(p, f, dry_run):
            files_decrypted += 1
            print(f"Decrypted: {p}")
    
    # NEW: Also restore from quarantine
    for p in sorted(QUARANTINE_DIR.rglob("*.locked")):
        if decrypt_file(p, f, dry_run):
            dest = SANDBOX / p.stem  # original filename without .locked
            if not dry_run:
                shutil.move(str(p.with_suffix("")), str(SANDBOX / p.stem))
            files_decrypted += 1
            print(f"Restored from quarantine: {dest}")
    
    if files_decrypted == 0:
        print("No .locked files found to decrypt")
        # disable restore mode
        if RESTORE_FLAG.exists():
            RESTORE_FLAG.unlink()
        return

    note = SANDBOX / "RANSOM_NOTE.txt"
    if note.exists() and not dry_run:
        note.unlink()
    
    # disable restore mode
    if RESTORE_FLAG.exists():
        RESTORE_FLAG.unlink()
    
    print(f"Decrypted {files_decrypted} files (dry_run={dry_run})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("--decrypt", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    
    if args.encrypt == args.decrypt:
        print("Specify exactly one of --encrypt or --decrypt")
        sys.exit(1)
    
    if args.encrypt:
        simulate_attack(dry_run=args.dry_run)
    else:
        restore_files(dry_run=args.dry_run)
