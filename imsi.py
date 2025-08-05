#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import csv
import subprocess
import threading
import time
import logging
import os
import queue
import signal

IMSI_DB = None  # Will hold the path to CSV after upload
LOG_FILE = os.path.expanduser("~/imsi_scanner.log")

log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        log_queue.put(log_entry)

logger = logging.getLogger("IMSI_GUI")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
queue_handler = QueueHandler()
queue_handler.setLevel(logging.INFO)
queue_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(file_handler)
logger.addHandler(queue_handler)

logger.info("=== IMSI Scanner GUI Started ===")

def get_imsi_by_phone(phone):
    if IMSI_DB is None:
        logger.warning("Attempt to lookup IMSI by phone but no CSV loaded")
        return None
    logger.info(f"Looking up IMSI for phone number: {phone}")
    try:
        with open(IMSI_DB, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('phone', '').strip() == phone:
                    logger.info(f"Match found: {row.get('imsi', '')}")
                    return row.get('imsi', '')
    except Exception as e:
        logger.error(f"Error reading IMSI DB: {e}")
    return None
import re
def scan_frequency(freq, target_imsi, stop_event):
    logger.info(f"[LIVEMON] Starting grgsm_livemon on {freq} Hz")
    result_event = threading.Event()

    try:
        livemon_proc = subprocess.Popen(['grgsm_livemon', f'--fc={freq} --no-gui'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        universal_newlines=True)

        def read_livemon_output():
            for line in livemon_proc.stdout:
                if stop_event.is_set():
                    break
                logger.info(f"[LIVEMON] {line.strip()}")

        threading.Thread(target=read_livemon_output, daemon=True).start()

        # Start tshark listener in background
        tshark_thread = threading.Thread(target=monitor_imsi, args=(target_imsi, stop_event, result_event))
        tshark_thread.start()

        # Wait up to 5 seconds for result
        result_event.wait(timeout=5)
        if result_event.is_set():
            logger.info("[SCAN] IMSI found, halting scan")
            stop_event.set()

        livemon_proc.terminate()
        livemon_proc.wait(timeout=2)
        logger.info(f"[LIVEMON] Stopped grgsm_livemon on {freq} Hz")

    except Exception as e:
        logger.error(f"[LIVEMON] Error: {e}")
def scan_frequencies():
    logger.info("[SCANNER] Running grgsm_scanner...")
    try:
        process = subprocess.Popen(['grgsm_scanner', '-b', 'GSM900'],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   universal_newlines=True)

        freqs = []
        freq_pattern = re.compile(r"Freq:\s+([\d.]+)M", re.IGNORECASE)

        for line in process.stdout:
            line = line.strip()
            logger.info(f"[SCANNER] {line}")
            match = freq_pattern.search(line)
            if match:
                freq = match.group(1)
                freqs.append(f"{freq}M")  # Format for livemon
                logger.info(f"[SCANNER] Extracted frequency: {freq}M")
        process.wait()
        return freqs
    except Exception as e:
        logger.error(f"[SCANNER] Frequency scan failed: {e}")
        return []

def monitor_imsi(target_imsi, stop_event, result_event):
    try:
        with subprocess.Popen(
            ['sudo', 'tshark', '-i', 'lo', '-Y', 'e212.imsi',
             '-T', 'fields', '-e', 'frame.time', '-e', 'e212.imsi', '-l'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True
        ) as tshark_proc:
            for line in tshark_proc.stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                logger.info(f"[TSHARK] {line}")
                if target_imsi in line:
                    logger.info(f"[TSHARK] IMSI FOUND: {target_imsi}")
                    result_event.set()
                    messagebox.showinfo("IMSI Found!", f"Target IMSI {target_imsi} detected:\n{line}")
                    break
            tshark_proc.terminate()
    except Exception as e:
        logger.error(f"[TSHARK] Error: {e}")

def start_scan(imsi_input, phone_input):
    logger.info(f"Scan started with IMSI: '{imsi_input}', Phone: '{phone_input}'")
    # Priority: IMSI field if filled, else phone lookup
    imsi = imsi_input.strip() if imsi_input.strip() else None
    if not imsi and phone_input.strip():
        if IMSI_DB is None:
            messagebox.showwarning("CSV not loaded", "Please upload CSV before searching by phone number.")
            return
        imsi = get_imsi_by_phone(phone_input.strip())
    if not imsi:
        logger.warning("IMSI not found or input invalid.")
        messagebox.showerror("Error", "IMSI or phone number not found.")
        return

    frequencies = scan_frequencies()
    if not frequencies:
        messagebox.showerror("Error", "No frequencies found.")
        logger.warning("No frequencies returned by scanner.")
        return

    def scanning_thread():
    	stop_event = threading.Event()
    	while not stop_event.is_set():
        	logger.info("[SCAN] Starting new frequency scan cycle...")
        	for freq in frequencies:
            		if stop_event.is_set():
                		logger.info("IMSI found, stopping scan loop.")
                		return
            		scan_frequency(freq, imsi, stop_event)
        	logger.info("[SCAN] Frequency cycle complete. Restarting in 3 seconds...")
        	time.sleep(3)  # pause between full cycles to avoid hammering SDR
	
    threading.Thread(target=scanning_thread, daemon=True).start()

def upload_csv():
    global IMSI_DB
    file_path = filedialog.askopenfilename(
        title="Select IMSI-Phone CSV",
        filetypes=[("CSV files", "*.csv")])
    if file_path:
        IMSI_DB = file_path
        logger.info(f"CSV loaded: {IMSI_DB}")
        messagebox.showinfo("CSV Loaded", f"Loaded IMSI database:\n{IMSI_DB}")
        # Enable phone number entry and search button
        phone_entry.config(state='normal')
        start_btn.config(state='normal')
    else:
        logger.info("CSV load cancelled or failed")

# --- GUI Setup ---

root = tk.Tk()
root.title("IMSI Scanner GUI")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# IMSI input
tk.Label(frame, text="Enter IMSI Number:").grid(row=0, column=0, sticky="w")
imsi_entry = tk.Entry(frame, width=30)
imsi_entry.grid(row=0, column=1, pady=3)

# Phone input
tk.Label(frame, text="Enter Phone Number:").grid(row=1, column=0, sticky="w")
phone_entry = tk.Entry(frame, width=30, state='disabled')  # disabled until CSV loaded
phone_entry.grid(row=1, column=1, pady=3)

# Upload CSV button
upload_btn = tk.Button(frame, text="Upload IMSI-Phone CSV", command=upload_csv)
upload_btn.grid(row=2, column=0, columnspan=2, pady=5)

# Start scan button
start_btn = tk.Button(frame, text="Start Scan", command=lambda: start_scan(imsi_entry.get(), phone_entry.get()))
start_btn.grid(row=3, column=0, columnspan=2, pady=10)

# Log output
log_box = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled', bg='black', fg='lightgreen')
log_box.pack(padx=10, pady=10)

def update_log_display():
    while not log_queue.empty():
        msg = log_queue.get()
        log_box.config(state='normal')
        log_box.insert(tk.END, msg + '\n')
        log_box.see(tk.END)
        log_box.config(state='disabled')
    root.after(100, update_log_display)

root.after(100, update_log_display)
root.mainloop()
