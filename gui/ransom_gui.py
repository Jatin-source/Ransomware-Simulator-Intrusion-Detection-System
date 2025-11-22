#!/usr/bin/env python3
"""
ransom_gui.py - simple Tkinter ransom window for demo use only.
Shows ransom message and asks for key. On correct key, calls safe_simulator.py --decrypt.
"""
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import subprocess

KEY_PATH = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/config/key.bin")
SIM_PATH = Path("/home/jatin/Desktop/Ransomware-Simulator-and-IDS/simulator/safe_simulator.py")
VENV_PY = "/home/jatin/Desktop/Ransomware-Simulator-and-IDS/venv/bin/python"


def try_key():
    entered = entry.get().strip().encode()
    if not KEY_PATH.exists():
        messagebox.showerror("Error", "No key found on system (key.bin missing).")
        return
    real_key = KEY_PATH.read_bytes().strip()
    if entered == real_key:
        # call decrypt routine
        subprocess.Popen([VENV_PY, str(SIM_PATH), "--decrypt"])
        messagebox.showinfo("Success", "Key correct — restoring files. See sandbox.")
        root.destroy()
    else:
        messagebox.showerror("Wrong key", "Incorrect key. Try again.")

def submit_key(event=None):
    """Handle both button click and Enter key"""
    entered = entry.get().strip().encode()
    if not KEY_PATH.exists():
        messagebox.showerror("Error", "No key found on system (key.bin missing).")
        return
    real_key = KEY_PATH.read_bytes().strip()
    if entered == real_key:
        subprocess.Popen([VENV_PY, str(SIM_PATH), "--decrypt"])
        messagebox.showinfo("Success", "Key correct — restoring files. See sandbox.")
        root.destroy()
    else:
        messagebox.showerror("Wrong key", "Incorrect key. Try again.")

root = tk.Tk()
root.title("Demo: Files locked — Recovery window")
root.geometry("500x300")

# Add warning style
warning_frame = tk.Frame(root, bg='red', padx=10, pady=10)
warning_frame.pack(fill='x', pady=20)
tk.Label(warning_frame, 
         text="⚠️ DEMO: Files appear locked — safe simulation ⚠️",
         bg='red', fg='white', font=('Arial', 12, 'bold')).pack()

# Main content frame setup
content_frame = tk.Frame(root)
content_frame.pack(pady=20)

# Entry field that binds to Enter key
entry = tk.Entry(content_frame, width=60, show="*")
entry.pack(pady=10)
entry.bind('<Return>', submit_key)  # Bind Enter key to submit

# Button frame with submit using same handler
button_frame = tk.Frame(content_frame)
button_frame.pack(pady=20)
submit_btn = tk.Button(button_frame, text="Submit Key", 
                      command=submit_key,  # Use same handler
                      bg='green', fg='white', width=15)
submit_btn.pack(side='left', padx=10)

# Focus entry field on startup
entry.focus()

# Center window
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry('{}x{}+{}+{}'.format(width, height, x, y))

root.mainloop()