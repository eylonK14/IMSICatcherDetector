#!/usr/bin/env python3
# For lawful research / lab use only.
"""
Enhanced IMSI/TMSI Scanner GUI

This application provides:
- Logs tab
- Frequency Scan tab (grgsm_scanner)
- IMSI Scan tab (legacy synchronous helpers)
- NEW: "TMSI Attach" tab (asyncio-based) to capture IMSI→TMSI mappings
       by correlating IMSI-bearing messages with TMSI assignment messages
       (Location Updating Accept / TMSI Reallocation Command) using tshark +
       grgsm_livemon_headless.

Architecture (TMSI tab):
- A dedicated asyncio event loop runs in a background thread.
- grgsm_livemon_headless is launched (async) per selected frequency.
- A single tshark (async) runs on lo, consuming GSMTAP (UDP/4729).
- Correlation uses a TTL cache keyed by (ARFCN, timeslot) and fallback (LAC, Cell).
- Results are pushed via a thread-safe Queue and consumed in Tkinter via root.after().
- CSV is appended (header if needed) and flushed on every write.
- Robust error handling and cooperative shutdown.

Python: 3.8+
External tools expected in PATH / proper perms:
  - grgsm_scanner
  - grgsm_livemon_headless
  - tshark
"""

import asyncio
import csv
import logging
import os
import queue
import re
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

# ------------------ Global logger & queue plumbing ------------------

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

logger.info("=== Enhanced IMSI Scanner GUI Started ===")


# ------------------ GUI Application ------------------

class IMSIScannerGUI:
    """
    Main GUI class.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced IMSI Scanner GUI")

        # Storage for scanned frequencies
        self.scanned_frequencies = []
        self.selected_frequencies = []

        # Storage for packet parameters (IMSI tab)
        self.packet_params = {
            'frame.time': tk.BooleanVar(value=True),
            'e212.imsi': tk.BooleanVar(value=True),
            'e212.mcc': tk.BooleanVar(value=False),
            'e212.mnc': tk.BooleanVar(value=False),
            'gsm_a.lac': tk.BooleanVar(value=False),
            'gsm_a.rr.cell_id': tk.BooleanVar(value=False)
        }

        # Log filters
        self.log_filters = {
            'SCANNER': tk.BooleanVar(value=True),
            'LIVEMON': tk.BooleanVar(value=True),
            'TSHARK': tk.BooleanVar(value=True),
            'SCAN': tk.BooleanVar(value=True),
            'GENERAL': tk.BooleanVar(value=True)
        }

        # Antenna options (placeholder)
        self.antenna_options = ['Default', 'Antenna 0', 'Antenna 1', 'Antenna 2']

        # Stop event for (legacy) IMSI scan
        self.stop_scan_event = threading.Event()

        # ------------------ Async engine for TMSI tab ------------------
        # Asyncio loop runs in a background thread to keep Tkinter responsive.
        self.async_loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self._async_loop_thread, daemon=True)
        self.loop_thread.start()

        # TMSI tab runtime state
        self.tmsi_status_var = tk.StringVar(value="Idle")
        self.tmsi_csv_path_var = tk.StringVar(value="")  # Chosen or auto path
        self.tmsi_ttl_var = tk.IntVar(value=10)          # TTL seconds for correlation
        self.tmsi_dedup_var = tk.BooleanVar(value=True)  # Deduplicate IMSI/TMSI pairs
        self.tmsi_running = False
        self.tmsi_stop_event = threading.Event()         # Cross-thread stop flag
        self.tmsi_ui_queue = queue.Queue()               # Mapping dicts -> UI/CSV
        self.tmsi_csv_handle = None
        self.tmsi_main_future = None

        # Housekeeping of async subprocesses/tasks (accessed from the async loop thread)
        self._tmsi_procs = []  # list of asyncio subprocess handles (livemon + tshark)
        self._tmsi_tasks = set()

        self.setup_ui()

    # ------------------ Tkinter setup ------------------

    def setup_ui(self):
        # Initialize log message storage
        self.all_log_messages = []
        self.auto_scroll = True

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Create tabs
        self.logs_tab = ttk.Frame(self.notebook)
        self.freq_scan_tab = ttk.Frame(self.notebook)
        self.imsi_scan_tab = ttk.Frame(self.notebook)
        self.tmsi_tab = ttk.Frame(self.notebook)  # NEW

        # Add tabs to notebook
        self.notebook.add(self.logs_tab, text='Logs')
        self.notebook.add(self.freq_scan_tab, text='Frequency Scan')
        self.notebook.add(self.imsi_scan_tab, text='IMSI Scan')
        self.notebook.add(self.tmsi_tab, text='TMSI Attach')  # NEW

        # Setup each tab
        self.setup_logs_tab()
        self.setup_freq_scan_tab()
        self.setup_imsi_scan_tab()
        self.setup_tmsi_tab()  # NEW

        # Start periodic update loops
        self.update_log_display()
        self.update_tmsi_display()  # NEW

    def setup_logs_tab(self):
        """Setup the Logs tab with scrolling log output"""
        # Filter controls frame
        filter_frame = ttk.LabelFrame(self.logs_tab, text="Log Filters", padding=5)
        filter_frame.pack(fill='x', padx=10, pady=(10, 5))

        # Create filter checkboxes
        filter_labels = {
            'SCANNER': 'Scanner',
            'LIVEMON': 'Livemon',
            'TSHARK': 'Tshark',
            'SCAN': 'Scan Control',
            'GENERAL': 'General'
        }

        # First row of filters
        filters_row1 = ttk.Frame(filter_frame)
        filters_row1.pack(fill='x')

        for i, (key, label) in enumerate(filter_labels.items()):
            cb = ttk.Checkbutton(
                filters_row1,
                text=label,
                variable=self.log_filters[key],
                command=self.refresh_log_display
            )
            cb.pack(side='left', padx=10, pady=2)

        # Filter control buttons
        ttk.Button(filters_row1, text="Enable All", command=self.enable_all_filters).pack(side='left', padx=10)
        ttk.Button(filters_row1, text="Disable All", command=self.disable_all_filters).pack(side='left', padx=5)

        # Log stats label
        self.log_stats_label = ttk.Label(filter_frame, text="Total: 0 messages (0 displayed)")
        self.log_stats_label.pack(anchor='e', padx=10, pady=(5, 0))

        # Log output
        self.log_box = scrolledtext.ScrolledText(
            self.logs_tab, width=100, height=25,
            state='disabled', bg='black', fg='lightgreen',
            font=('Consolas', 9)
        )
        self.log_box.pack(padx=10, pady=5, fill='both', expand=True)

        # Configure tags for different log types (colors)
        self.log_box.tag_config('SCANNER', foreground='cyan')
        self.log_box.tag_config('LIVEMON', foreground='yellow')
        self.log_box.tag_config('TSHARK', foreground='lime')
        self.log_box.tag_config('SCAN', foreground='orange')
        self.log_box.tag_config('ERROR', foreground='red')
        self.log_box.tag_config('WARNING', foreground='gold')
        self.log_box.tag_config('GENERAL', foreground='lightgreen')

        # Control buttons frame
        button_frame = ttk.Frame(self.logs_tab)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save Log", command=self.save_log).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Auto-scroll", command=self.toggle_autoscroll).pack(side='left', padx=5)

    def setup_freq_scan_tab(self):
        """Setup the Frequency Scan tab"""
        # Main frame
        main_frame = ttk.Frame(self.freq_scan_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))

        # Band selection
        ttk.Label(control_frame, text="Band:").pack(side='left', padx=(0, 5))
        self.band_var = tk.StringVar(value='GSM900')
        band_combo = ttk.Combobox(
            control_frame, textvariable=self.band_var,
            values=['GSM900', 'DCS1800', 'GSM850', 'PCS1900'],
            width=15, state='readonly'
        )
        band_combo.pack(side='left', padx=(0, 10))

        # Scan button
        self.scan_freq_btn = ttk.Button(
            control_frame, text="Scan Frequencies",
            command=self.scan_frequencies_threaded
        )
        self.scan_freq_btn.pack(side='left', padx=5)

        # Refresh button
        self.refresh_freq_btn = ttk.Button(
            control_frame, text="Refresh",
            command=self.scan_frequencies_threaded
        )
        self.refresh_freq_btn.pack(side='left', padx=5)

        # Add manual frequency button
        self.add_manual_freq_btn = ttk.Button(
            control_frame, text="Add Manual",
            command=self.add_manual_frequency
        )
        self.add_manual_freq_btn.pack(side='left', padx=5)

        # Frequency list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill='both', expand=True)

        ttk.Label(list_frame, text="Found Frequencies (Select for IMSI/TMSI Scans):").pack(anchor='w')

        # Frequency listbox with scrollbar
        freq_scroll = ttk.Scrollbar(list_frame)
        freq_scroll.pack(side='right', fill='y')

        self.freq_listbox = tk.Listbox(
            list_frame, selectmode=tk.MULTIPLE,
            yscrollcommand=freq_scroll.set, height=15
        )
        self.freq_listbox.pack(side='left', fill='both', expand=True)
        freq_scroll.config(command=self.freq_listbox.yview)

        # Select all/none buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=5)

        ttk.Button(button_frame, text="Select All", command=self.select_all_frequencies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Select None", command=self.clear_frequency_selection).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Apply Selection", command=self.apply_frequency_selection).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected_frequencies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_all_frequencies).pack(side='left', padx=5)

        # Status label
        self.freq_status_label = ttk.Label(main_frame, text="No frequencies scanned yet")
        self.freq_status_label.pack(pady=5)

    def setup_imsi_scan_tab(self):
        """Setup the IMSI Scan tab (legacy helpers retained)"""
        # Main frame
        main_frame = ttk.Frame(self.imsi_scan_tab)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Target Configuration", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))

        # IMSI input
        ttk.Label(input_frame, text="IMSI Number:").grid(row=0, column=0, sticky="w", pady=3)
        self.imsi_entry = ttk.Entry(input_frame, width=30)
        self.imsi_entry.grid(row=0, column=1, pady=3, padx=(5, 0))

        # Phone input
        ttk.Label(input_frame, text="Phone Number:").grid(row=1, column=0, sticky="w", pady=3)
        self.phone_entry = ttk.Entry(input_frame, width=30, state='disabled')
        self.phone_entry.grid(row=1, column=1, pady=3, padx=(5, 0))

        # Upload CSV button
        self.upload_btn = ttk.Button(input_frame, text="Upload IMSI-Phone CSV", command=self.upload_csv)
        self.upload_btn.grid(row=2, column=0, columnspan=2, pady=5)

        # Antenna selection
        ttk.Label(input_frame, text="Antenna:").grid(row=3, column=0, sticky="w", pady=3)
        self.antenna_var = tk.StringVar(value=self.antenna_options[0])
        antenna_combo = ttk.Combobox(
            input_frame, textvariable=self.antenna_var,
            values=self.antenna_options, width=28, state='readonly'
        )
        antenna_combo.grid(row=3, column=1, pady=3, padx=(5, 0))

        # Packet parameters frame
        params_frame = ttk.LabelFrame(main_frame, text="Packet Parameters to Display", padding=10)
        params_frame.pack(fill='x', pady=(0, 10))

        # Create checkboxes for packet parameters
        params_grid = ttk.Frame(params_frame)
        params_grid.pack()

        param_labels = {
            'frame.time': 'Frame Time',
            'e212.imsi': 'IMSI',
            'e212.mcc': 'MCC',
            'e212.mnc': 'MNC',
            'gsm_a.lac': 'LAC',
            'gsm_a.rr.cell_id': 'Cell ID'
        }

        row = 0
        col = 0
        for param, label in param_labels.items():
            cb = ttk.Checkbutton(params_grid, text=label, variable=self.packet_params[param])
            cb.grid(row=row, column=col, sticky='w', padx=10, pady=2)
            col += 1
            if col > 2:  # 3 columns
                col = 0
                row += 1

        # Selected frequencies display
        freq_frame = ttk.LabelFrame(main_frame, text="Selected Frequencies for Scan", padding=10)
        freq_frame.pack(fill='x', pady=(0, 10))

        self.selected_freq_label = ttk.Label(freq_frame, text="No frequencies selected")
        self.selected_freq_label.pack()

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x')

        self.start_scan_btn = ttk.Button(
            control_frame, text="Start IMSI Scan",
            command=self.start_imsi_scan
        )
        self.start_scan_btn.pack(side='left', padx=5)

        self.stop_scan_btn = ttk.Button(
            control_frame, text="Stop Scan",
            command=self.stop_imsi_scan, state='disabled'
        )
        self.stop_scan_btn.pack(side='left', padx=5)

    # ------------------ NEW: TMSI Attach Tab ------------------

    def setup_tmsi_tab(self):
        """
        Setup the 'TMSI Attach' tab UI and state.
        """
        outer = ttk.Frame(self.tmsi_tab)
        outer.pack(fill='both', expand=True, padx=10, pady=10)

        # Row: CSV selection + Start/Stop + Status
        top = ttk.Frame(outer)
        top.pack(fill='x', pady=(0, 8))

        ttk.Button(top, text="Choose CSV…", command=self.choose_tmsi_csv).pack(side='left', padx=(0, 8))

        self.tmsi_csv_label = ttk.Label(top, text="No file chosen — default will be used on start")
        self.tmsi_csv_label.pack(side='left', padx=(0, 8))

        ttk.Label(top, text="Status:").pack(side='left', padx=(10, 4))
        self.tmsi_status_lbl = ttk.Label(top, textvariable=self.tmsi_status_var)
        self.tmsi_status_lbl.pack(side='left')

        # Row: Controls
        ctrl = ttk.Frame(outer)
        ctrl.pack(fill='x', pady=(0, 8))

        self.tmsi_start_btn = ttk.Button(ctrl, text="Start TMSI Capture", command=self.start_tmsi_capture)
        self.tmsi_start_btn.pack(side='left', padx=(0, 6))

        self.tmsi_stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop_tmsi_capture, state='disabled')
        self.tmsi_stop_btn.pack(side='left', padx=(0, 6))

        # Settings (TTL & Dedup)
        settings = ttk.LabelFrame(outer, text="Correlation Settings", padding=8)
        settings.pack(fill='x', pady=(0, 8))

        ttk.Label(settings, text="TTL (seconds):").pack(side='left', padx=(0, 6))
        self.ttl_spin = ttk.Spinbox(settings, from_=1, to=120, textvariable=self.tmsi_ttl_var, width=5)
        self.ttl_spin.pack(side='left', padx=(0, 12))

        self.dedup_cb = ttk.Checkbutton(settings, text="Deduplicate (IMSI,TMSI) pairs", variable=self.tmsi_dedup_var)
        self.dedup_cb.pack(side='left')

        # Output / mappings box
        out_frame = ttk.LabelFrame(outer, text="IMSI → TMSI Mappings", padding=8)
        out_frame.pack(fill='both', expand=True)

        self.tmsi_text = scrolledtext.ScrolledText(out_frame, height=18, width=110, state='disabled',
                                                   font=('Consolas', 9))
        self.tmsi_text.pack(fill='both', expand=True)

        # Hint header
        self._append_tmsi_text(
            "timestamp_iso, IMSI, TMSI, LAC, CellID, ARFCN, TS, source_message\n", bold=True
        )

    # ------------------ Logs Tab helpers ------------------

    def clear_log(self):
        """Clear the log display"""
        self.log_box.config(state='normal')
        self.log_box.delete(1.0, tk.END)
        self.log_box.config(state='disabled')
        self.all_log_messages = []
        self.update_log_stats()
        logger.info("Log display cleared")

    def save_log(self):
        """Save visible logs to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                content = self.log_box.get(1.0, tk.END)
                with open(file_path, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Log saved to {file_path}")
                logger.info(f"Log saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")
                logger.error(f"Failed to save log: {e}")

    def enable_all_filters(self):
        """Enable all log filters"""
        for var in self.log_filters.values():
            var.set(True)
        self.refresh_log_display()

    def disable_all_filters(self):
        """Disable all log filters"""
        for var in self.log_filters.values():
            var.set(False)
        self.refresh_log_display()

    def toggle_autoscroll(self):
        """Toggle auto-scroll functionality"""
        self.auto_scroll = not self.auto_scroll
        msg = "Auto-scroll enabled" if self.auto_scroll else "Auto-scroll disabled"
        logger.info(msg)

    def get_log_category(self, msg):
        """Determine the category of a log message"""
        # Check for log level first
        if '[ERROR]' in msg:
            return 'ERROR'
        elif '[WARNING]' in msg:
            return 'WARNING'
        # Check for specific prefixes in the message
        elif '[SCANNER]' in msg:
            return 'SCANNER'
        elif '[LIVEMON]' in msg:
            return 'LIVEMON'
        elif '[TSHARK]' in msg:
            return 'TSHARK'
        elif '[SCAN]' in msg:
            return 'SCAN'
        else:
            return 'GENERAL'

    def should_display_message(self, msg):
        """Check if a message should be displayed based on filters"""
        category = self.get_log_category(msg)
        # ERROR and WARNING always show if any filter is enabled
        if category in ['ERROR', 'WARNING']:
            return any(var.get() for var in self.log_filters.values())
        # Check specific category filter
        if category in self.log_filters:
            return self.log_filters[category].get()
        return self.log_filters['GENERAL'].get()

    def update_log_stats(self):
        """Update the log statistics label"""
        total_msgs = len(self.all_log_messages)
        displayed_msgs = sum(1 for msg in self.all_log_messages if self.should_display_message(msg))
        self.log_stats_label.config(text=f"Total: {total_msgs} messages ({displayed_msgs} displayed)")

    def refresh_log_display(self):
        """Refresh the log display based on current filters"""
        self.log_box.config(state='normal')
        self.log_box.delete(1.0, tk.END)

        # Re-display filtered messages with colors
        for msg in self.all_log_messages:
            if self.should_display_message(msg):
                category = self.get_log_category(msg)
                start_pos = self.log_box.index(tk.END)
                self.log_box.insert(tk.END, msg + '\n')
                end_pos = self.log_box.index(tk.END)
                self.log_box.tag_add(category, start_pos, end_pos)

        if self.auto_scroll:
            self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

        # Update stats
        self.update_log_stats()

    def update_log_display(self):
        """Update log display from queue"""
        while not log_queue.empty():
            msg = log_queue.get()
            # Store all messages
            self.all_log_messages.append(msg)

            # Only display if filter allows
            if self.should_display_message(msg):
                self.log_box.config(state='normal')

                # Add message with color tag
                category = self.get_log_category(msg)
                start_pos = self.log_box.index(tk.END)
                self.log_box.insert(tk.END, msg + '\n')
                end_pos = self.log_box.index(tk.END)
                self.log_box.tag_add(category, start_pos, end_pos)

                if self.auto_scroll:
                    self.log_box.see(tk.END)
                self.log_box.config(state='disabled')

        # Keep only last 10000 messages to prevent memory issues
        if len(self.all_log_messages) > 10000:
            self.all_log_messages = self.all_log_messages[-9000:]

        # Update stats
        self.update_log_stats()

        self.root.after(100, self.update_log_display)

    # ------------------ Frequency scanning (legacy) ------------------

    def scan_frequencies_threaded(self):
        """Run frequency scan in a separate thread"""
        self.scan_freq_btn.config(state='disabled')
        self.refresh_freq_btn.config(state='disabled')
        self.freq_status_label.config(text="Scanning frequencies...")

        def scan_thread():
            frequencies = self.scan_frequencies()
            self.root.after(0, self.update_frequency_list, frequencies)

        threading.Thread(target=scan_thread, daemon=True).start()

    def scan_frequencies(self):
        """Scan for frequencies using grgsm_scanner"""
        band = self.band_var.get()
        logger.info(f"[SCANNER] Running grgsm_scanner for band {band}...")
        try:
            process = subprocess.Popen(
                ['grgsm_scanner', '-b', band],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )

            freqs = []
            freq_pattern = re.compile(r"Freq:\s+([\d.]+)M", re.IGNORECASE)

            for line in process.stdout:
                line = line.strip()
                logger.info(f"[SCANNER] {line}")
                match = freq_pattern.search(line)
                if match:
                    freq = match.group(1)
                    freqs.append(f"{freq}M")
                    logger.info(f"[SCANNER] Extracted frequency: {freq}M")
            process.wait()
            return freqs
        except Exception as e:
            logger.error(f"[SCANNER] Frequency scan failed: {e}")
            return []

    def update_frequency_list(self, frequencies):
        """Update the frequency listbox with scan results"""
        self.scanned_frequencies = frequencies
        self.freq_listbox.delete(0, tk.END)

        for freq in frequencies:
            self.freq_listbox.insert(tk.END, freq)

        self.scan_freq_btn.config(state='normal')
        self.refresh_freq_btn.config(state='normal')

        if frequencies:
            self.freq_status_label.config(text=f"Found {len(frequencies)} frequencies")
            logger.info(f"Frequency scan complete: {len(frequencies)} frequencies found")
        else:
            self.freq_status_label.config(text="No frequencies found")
            logger.warning("No frequencies found in scan")

    def add_manual_frequency(self):
        """Open dialog to add frequencies manually"""
        # Create a new dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Manual Frequencies")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Instructions
        instructions = ttk.Label(
            dialog,
            text="Enter frequencies (one per line or comma-separated):\n"
                 "Format: 935.2M or 935200000 (Hz)",
            wraplength=350
        )
        instructions.pack(padx=10, pady=10)

        # Text input area
        text_frame = ttk.Frame(dialog)
        text_frame.pack(fill='both', expand=True, padx=10, pady=5)

        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side='right', fill='y')

        freq_text = tk.Text(text_frame, height=8, width=40, yscrollcommand=text_scroll.set)
        freq_text.pack(side='left', fill='both', expand=True)
        text_scroll.config(command=freq_text.yview)

        # Example text
        freq_text.insert('1.0', "# Examples:\n935.2M\n960.0M\n935200000")

        # Button frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill='x', padx=10, pady=10)

        def validate_and_add():
            """Validate and add the entered frequencies"""
            text_content = freq_text.get('1.0', tk.END).strip()
            lines = text_content.split('\n')

            new_frequencies = []
            for line in lines:
                # Skip comments and empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Split by comma if multiple frequencies on one line
                freq_entries = [f.strip() for f in line.split(',')]

                for entry in freq_entries:
                    if not entry:
                        continue

                    # Parse frequency
                    freq = self.parse_frequency(entry)
                    if freq:
                        new_frequencies.append(freq)

            if new_frequencies:
                # Add to existing frequencies
                for freq in new_frequencies:
                    if freq not in self.scanned_frequencies:
                        self.scanned_frequencies.append(freq)
                        self.freq_listbox.insert(tk.END, freq)
                        logger.info(f"Manually added frequency: {freq}")

                self.freq_status_label.config(
                    text=f"Total {len(self.scanned_frequencies)} frequencies "
                         f"({len(new_frequencies)} manually added)"
                )
                messagebox.showinfo(
                    "Success",
                    f"Added {len(new_frequencies)} frequencies successfully!",
                    parent=dialog
                )
                dialog.destroy()
            else:
                messagebox.showwarning(
                    "Invalid Input",
                    "No valid frequencies found. Please check format.",
                    parent=dialog
                )

        def clear_text():
            """Clear the text area"""
            freq_text.delete('1.0', tk.END)

        ttk.Button(button_frame, text="Add", command=validate_and_add).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear", command=clear_text).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side='left', padx=5)

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

    def parse_frequency(self, freq_str):
        """Parse frequency string to standard format (e.g., 935.2M)"""
        freq_str = freq_str.strip()

        try:
            # Check if it's already in MHz format (e.g., 935.2M)
            if freq_str.upper().endswith('M'):
                freq_val = float(freq_str[:-1])
                if 100 <= freq_val <= 6000:  # Valid frequency range
                    return f"{freq_val}M"

            # Check if it's in Hz (e.g., 935200000)
            elif freq_str.isdigit() or '.' in freq_str:
                freq_hz = float(freq_str)
                if freq_hz > 1_000_000:  # Assume Hz if > 1MHz
                    freq_mhz = freq_hz / 1_000_000
                    if 100 <= freq_mhz <= 6000:  # Valid frequency range
                        return f"{freq_mhz}M"
                elif 100 <= freq_hz <= 6000:  # Already in MHz
                    return f"{freq_hz}M"

        except ValueError:
            pass

        logger.warning(f"Invalid frequency format: {freq_str}")
        return None

    def select_all_frequencies(self):
        """Select all frequencies in the listbox"""
        self.freq_listbox.select_set(0, tk.END)

    def clear_frequency_selection(self):
        """Clear frequency selection"""
        self.freq_listbox.select_clear(0, tk.END)

    def remove_selected_frequencies(self):
        """Remove selected frequencies from the list"""
        selected_indices = list(self.freq_listbox.curselection())

        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select frequencies to remove.")
            return

        # Confirm removal
        count = len(selected_indices)
        if messagebox.askyesno("Confirm Removal", f"Remove {count} selected frequencies?"):
            # Remove from back to front to maintain indices
            for index in reversed(selected_indices):
                freq = self.scanned_frequencies[index]
                self.scanned_frequencies.pop(index)
                self.freq_listbox.delete(index)
                logger.info(f"Removed frequency: {freq}")

            # Update status
            self.freq_status_label.config(text=f"Total {len(self.scanned_frequencies)} frequencies")

            # Clear selection from selected_frequencies if they were removed
            self.selected_frequencies = [f for f in self.selected_frequencies
                                        if f in self.scanned_frequencies]
            if self.selected_frequencies:
                freq_text = f"Selected {len(self.selected_frequencies)} frequencies: {', '.join(self.selected_frequencies[:5])}"
                if len(self.selected_frequencies) > 5:
                    freq_text += "..."
            else:
                freq_text = "No frequencies selected (removed frequencies were deselected)"
            self.selected_freq_label.config(text=freq_text)

    def clear_all_frequencies(self):
        """Clear all frequencies from the list"""
        if not self.scanned_frequencies:
            messagebox.showinfo("Empty List", "No frequencies to clear.")
            return

        if messagebox.askyesno("Confirm Clear", "Clear all frequencies from the list?"):
            self.scanned_frequencies = []
            self.selected_frequencies = []
            self.freq_listbox.delete(0, tk.END)
            self.freq_status_label.config(text="No frequencies in list")
            self.selected_freq_label.config(text="No frequencies selected")
            logger.info("Cleared all frequencies from list")

    def apply_frequency_selection(self):
        """Apply the selected frequencies for scanning tabs"""
        selected_indices = self.freq_listbox.curselection()
        self.selected_frequencies = [self.scanned_frequencies[i] for i in selected_indices]

        if self.selected_frequencies:
            freq_text = f"Selected {len(self.selected_frequencies)} frequencies: {', '.join(self.selected_frequencies[:5])}"
            if len(self.selected_frequencies) > 5:
                freq_text += "..."
        else:
            freq_text = "No frequencies selected"

        self.selected_freq_label.config(text=freq_text)
        logger.info(f"Frequencies selected for scans: {self.selected_frequencies}")
        messagebox.showinfo("Selection Applied", f"{len(self.selected_frequencies)} frequencies selected")

    # ------------------ IMSI Scan (legacy demo) ------------------

    def upload_csv(self):
        """Upload CSV file with IMSI-Phone mapping"""
        global IMSI_DB
        file_path = filedialog.askopenfilename(
            title="Select IMSI-Phone CSV",
            filetypes=[("CSV files", "*.csv")]
        )
        if file_path:
            IMSI_DB = file_path
            logger.info(f"CSV loaded: {IMSI_DB}")
            messagebox.showinfo("CSV Loaded", f"Loaded IMSI database:\n{IMSI_DB}")
            self.phone_entry.config(state='normal')
        else:
            logger.info("CSV load cancelled or failed")

    def get_imsi_by_phone(self, phone):
        """Lookup IMSI by phone number from CSV"""
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

    def start_imsi_scan(self):
        """Start scanning for target IMSI (legacy helper)"""
        # Get target IMSI
        imsi = self.imsi_entry.get().strip()
        if not imsi and self.phone_entry.get().strip():
            if IMSI_DB is None:
                messagebox.showwarning("CSV not loaded", "Please upload CSV before searching by phone number.")
                return
            imsi = self.get_imsi_by_phone(self.phone_entry.get().strip())

        if not imsi:
            logger.warning("IMSI not found or input invalid.")
            messagebox.showerror("Error", "IMSI or phone number not found.")
            return

        # Check if frequencies are selected
        if not self.selected_frequencies:
            messagebox.showwarning("No Frequencies", "Please select frequencies from the Frequency Scan tab first.")
            return

        # Disable start button, enable stop
        self.start_scan_btn.config(state='disabled')
        self.stop_scan_btn.config(state='normal')

        # Clear stop event
        self.stop_scan_event.clear()

        # Get selected packet parameters
        selected_params = [param for param, var in self.packet_params.items() if var.get()]

        # Start scanning thread
        def scanning_thread():
            logger.info(f"[SCAN] Starting IMSI scan for: {imsi}")
            logger.info(f"[SCAN] Using frequencies: {self.selected_frequencies}")
            logger.info(f"[SCAN] Using antenna: {self.antenna_var.get()}")
            logger.info(f"[SCAN] Displaying parameters: {selected_params}")

            while not self.stop_scan_event.is_set():
                logger.info("[SCAN] Starting new frequency scan cycle...")
                for freq in self.selected_frequencies:
                    if self.stop_scan_event.is_set():
                        logger.info("IMSI scan stopped by user.")
                        break
                    self.scan_frequency(freq, imsi, selected_params)

                if not self.stop_scan_event.is_set():
                    logger.info("[SCAN] Frequency cycle complete. Restarting in 3 seconds...")
                    time.sleep(3)

            # Re-enable buttons
            self.root.after(0, lambda: self.start_scan_btn.config(state='normal'))
            self.root.after(0, lambda: self.stop_scan_btn.config(state='disabled'))

        threading.Thread(target=scanning_thread, daemon=True).start()

    def stop_imsi_scan(self):
        """Stop the IMSI scan"""
        logger.info("Stopping IMSI scan...")
        self.stop_scan_event.set()
        self.stop_scan_btn.config(state='disabled')

    def scan_frequency(self, freq, target_imsi, selected_params):
        """Scan a specific frequency for target IMSI (legacy helper)"""
        logger.info(f"[LIVEMON] Starting grgsm_livemon on {freq}")
        result_event = threading.Event()

        try:
            # Build grgsm_livemon command
            cmd = ['grgsm_livemon_headless', f'--fc={freq}']

            livemon_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )

            def read_livemon_output():
                for line in livemon_proc.stdout:
                    if self.stop_scan_event.is_set():
                        break
                    logger.info(f"[LIVEMON] {line.strip()}")

            threading.Thread(target=read_livemon_output, daemon=True).start()

            # Start tshark listener
            tshark_thread = threading.Thread(
                target=self.monitor_imsi,
                args=(target_imsi, selected_params, result_event)
            )
            tshark_thread.start()

            # Wait for result or timeout
            result_event.wait(timeout=25)
            if result_event.is_set():
                logger.info("[SCAN] IMSI found, halting scan")
                self.stop_scan_event.set()

            livemon_proc.terminate()
            livemon_proc.wait(timeout=2)
            logger.info(f"[LIVEMON] Stopped grgsm_livemon on {freq}")

        except Exception as e:
            logger.error(f"[LIVEMON] Error: {e}")

    def monitor_imsi(self, target_imsi, selected_params, result_event):
        """Monitor for target IMSI using tshark (legacy helper)"""
        try:
            # Build tshark command with selected fields
            cmd = ['tshark', '-i', 'lo', '-Y', 'e212.imsi', '-T', 'fields']

            # Add selected fields
            for param in selected_params:
                cmd.extend(['-e', param])

            cmd.append('-l')

            with subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            ) as tshark_proc:
                for line in tshark_proc.stdout:
                    if self.stop_scan_event.is_set():
                        break
                    line = line.strip()
                    logger.info(f"[TSHARK] {line}")
                    if target_imsi in line:
                        logger.info(f"[TSHARK] IMSI FOUND: {target_imsi}")
                        result_event.set()
                        self.root.after(0, lambda: messagebox.showinfo(
                            "IMSI Found!",
                            f"Target IMSI {target_imsi} detected:\n{line}"
                        ))
                        break
                tshark_proc.terminate()
        except FileNotFoundError:
            logger.error("[TSHARK] tshark not found in PATH.")
        except Exception as e:
            logger.error(f"[TSHARK] Error: {e}")

    # ------------------ NEW: TMSI Attach controls ------------------

    def choose_tmsi_csv(self):
        """Choose output CSV path for TMSI mappings."""
        path = filedialog.asksaveasfilename(
            title="Choose output CSV",
            initialfile=f"tmsi_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if path:
            self.tmsi_csv_path_var.set(path)
            self.tmsi_csv_label.config(text=path)
        else:
            # No change; keep existing label text
            pass

    def start_tmsi_capture(self):
        """
        Start the asyncio-based TMSI capture pipeline:
        - Launch grgsm_livemon_headless per selected frequency.
        - Launch tshark on lo with GSMTAP filters.
        - Correlate IMSI→TMSI with TTL and dedup options.
        """
        if self.tmsi_running:
            return

        if not self.selected_frequencies:
            messagebox.showwarning("No Frequencies", "Please select frequencies in 'Frequency Scan' and Apply.")
            return

        # Prepare CSV path (default if none selected)
        if not self.tmsi_csv_path_var.get():
            auto = os.path.expanduser(
                f"~/tmsi_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            self.tmsi_csv_path_var.set(auto)
            self.tmsi_csv_label.config(text=auto)

        # Open CSV handle in main thread; write header if empty/new
        try:
            new_file = not os.path.exists(self.tmsi_csv_path_var.get()) or os.path.getsize(self.tmsi_csv_path_var.get()) == 0
            self.tmsi_csv_handle = open(self.tmsi_csv_path_var.get(), "a", newline="")
            self._tmsi_csv_writer = csv.writer(self.tmsi_csv_handle)
            if new_file:
                self._tmsi_csv_writer.writerow(
                    ["timestamp_iso", "imsi", "tmsi", "lac", "cell_id", "arfcn", "timeslot", "source_msg"]
                )
                self.tmsi_csv_handle.flush()
        except PermissionError as e:
            messagebox.showerror("CSV Error", f"Permission denied writing to CSV:\n{e}")
            return
        except Exception as e:
            messagebox.showerror("CSV Error", f"Failed to open CSV:\n{e}")
            return

        # Disable start / enable stop
        self.tmsi_start_btn.config(state='disabled')
        self.tmsi_stop_btn.config(state='normal')
        self.tmsi_status_var.set("Running")
        self.tmsi_running = True
        self.tmsi_stop_event.clear()

        # Schedule async main in the loop thread
        ttl = max(1, int(self.tmsi_ttl_var.get()))
        dedup = bool(self.tmsi_dedup_var.get())

        logger.info("[SCAN] Starting TMSI capture...")
        logger.info(f"[SCAN] Using frequencies: {self.selected_frequencies}")
        logger.info(f"[SCAN] TTL: {ttl}s, Dedup: {dedup}")
        logger.info(f"[SCAN] CSV: {self.tmsi_csv_path_var.get()}")

        self.tmsi_main_future = asyncio.run_coroutine_threadsafe(
            self.tmsi_async_main(self.selected_frequencies, ttl, dedup),
            self.async_loop
        )

    def stop_tmsi_capture(self):
        """
        Signal stop to async tasks and processes, and restore UI when done.
        """
        if not self.tmsi_running:
            return
        self.tmsi_stop_event.set()
        self.tmsi_status_var.set("Stopping")
        self.tmsi_stop_btn.config(state='disabled')

        # Ask the async loop to terminate all running TMSI tasks and procs
        fut = asyncio.run_coroutine_threadsafe(self._terminate_tmsi_async(), self.async_loop)

        def after_stop():
            # Close CSV cleanly
            try:
                if self.tmsi_csv_handle:
                    self.tmsi_csv_handle.flush()
                    self.tmsi_csv_handle.close()
            except Exception:
                pass
            self.tmsi_csv_handle = None

            self.tmsi_running = False
            self.tmsi_status_var.set("Stopped")
            self.tmsi_start_btn.config(state='normal')

        # Non-blocking: poll the future without freezing UI
        def check_future():
            if fut.done():
                _ = fut.result() if not fut.cancelled() else None
                self.root.after(0, after_stop)
            else:
                self.root.after(100, check_future)

        self.root.after(100, check_future)

    # ------------------ Async Engine (TMSI tab) ------------------

    def _async_loop_thread(self):
        """Entry point for the background asyncio loop."""
        asyncio.set_event_loop(self.async_loop)
        self.async_loop.run_forever()

    async def _terminate_tmsi_async(self):
        """
        Terminates all async tasks and subprocesses for the TMSI tab.
        Called inside the asyncio loop thread.
        """
        # Terminate subprocesses gently
        for proc in list(self._tmsi_procs):
            try:
                if proc.returncode is None:
                    proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.error(f"[SCAN] Error terminating process: {e}")

        # Give them a moment
        await asyncio.sleep(0.3)

        # Force kill still-alive processes
        for proc in list(self._tmsi_procs):
            try:
                if proc.returncode is None:
                    proc.kill()
            except Exception:
                pass

        self._tmsi_procs.clear()

        # Cancel tasks
        for t in list(self._tmsi_tasks):
            t.cancel()
        self._tmsi_tasks.clear()

    async def tmsi_async_main(self, freqs, ttl_seconds, dedup_enabled):
        """
        Async main for TMSI Attach mode.

        - Spawns grgsm_livemon_headless per frequency (to feed GSMTAP on UDP/4729).
        - Runs one tshark on lo with display filter for IMSI OR (TMSI & desired MM types).
        - Correlates IMSI-bearing lines with TMSI assignment lines within TTL.
        - Emits mapping dicts to self.tmsi_ui_queue.
        """
        # Delay slight to allow livemon to start producing
        start_ok = True

        # Launch livemon for each frequency
        for f in freqs:
            cmd = ['grgsm_livemon_headless', f'--fc={f}']
            try:
                p = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
            except FileNotFoundError:
                logger.error("[LIVEMON] grgsm_livemon_headless not found in PATH.")
                start_ok = False
                continue
            except Exception as e:
                logger.error(f"[LIVEMON] Failed to start for {f}: {e}")
                start_ok = False
                continue

            self._tmsi_procs.append(p)
            task = asyncio.create_task(self._reader_task(p, prefix='[LIVEMON]'))
            self._tmsi_tasks.add(task)
            task.add_done_callback(lambda t: self._tmsi_tasks.discard(t))

            logger.info(f"[LIVEMON] Started for {f}")

        if not start_ok:
            logger.warning("[SCAN] Some livemon processes failed to start. Capture may be incomplete.")

        # Correlation caches
        # Keyed by (arfcn, timeslot) -> {imsi, ts_epoch, lac, cell_id}
        recent_imsi_by_chan = {}
        # Keyed by (lac, cell_id) -> list of (ts_epoch, imsi)
        recent_imsi_by_cell = {}

        # Dedup set for (imsi,tmsi) if enabled (within this run)
        dedup_set = set()

        # Prune coroutine to keep caches fresh
        async def prune_task():
            while not self.tmsi_stop_event.is_set():
                now = time.time()
                # Prune chan
                stale = [k for k, v in recent_imsi_by_chan.items() if now - v['ts_epoch'] > ttl_seconds]
                for k in stale:
                    recent_imsi_by_chan.pop(k, None)
                # Prune cell (keep last N entries per cell, and TTL)
                for k, arr in list(recent_imsi_by_cell.items()):
                    recent_imsi_by_cell[k] = [
                        (ts, im) for (ts, im) in arr if now - ts <= ttl_seconds
                    ]
                    if not recent_imsi_by_cell[k]:
                        recent_imsi_by_cell.pop(k, None)
                await asyncio.sleep(1.0)

        pt = asyncio.create_task(prune_task())
        self._tmsi_tasks.add(pt)
        pt.add_done_callback(lambda t: self._tmsi_tasks.discard(t))

        # Start tshark with restart policy (up to 2 restarts)
        restarts_left = 2
        while not self.tmsi_stop_event.is_set():
            tshark_cmd = [
                'tshark',
                '-n',                      # no name resolution
                '-i', 'lo',
                '-f', 'udp port 4729',    # capture filter
                '-Y', 'e212.imsi || (gsm_a.tmsi && (gsm_a.dtap.msg_mm_type == 0x02 || gsm_a.dtap.msg_mm_type == 0x10))',
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'e212.imsi',
                '-e', 'gsm_a.tmsi',
                '-e', 'gsm_a.dtap.msg_mm_type',
                '-e', 'gsm_a.lac',
                '-e', 'gsm_a.rr.cell_id',
                '-e', 'gsmtap.arfcn',
                '-e', 'gsmtap.timeslot',
                '-E', 'separator=\t',
                '-l'
            ]

            try:
                tshark_proc = await asyncio.create_subprocess_exec(
                    *tshark_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
            except FileNotFoundError:
                logger.error("[TSHARK] tshark not found in PATH.")
                break
            except Exception as e:
                logger.error(f"[TSHARK] Failed to start: {e}")
                break

            self._tmsi_procs.append(tshark_proc)
            logger.info("[TSHARK] Started.")

            # Reader
            try:
                while not self.tmsi_stop_event.is_set():
                    line = await tshark_proc.stdout.readline()
                    if not line:
                        break  # EOF
                    s = line.decode(errors='replace').rstrip("\n")
                    if s:
                        logger.info(f"[TSHARK] {s}")
                    # Parse & correlate
                    mapping = self.tmsi_handle_tshark_line(
                        s, recent_imsi_by_chan, recent_imsi_by_cell, ttl_seconds
                    )
                    # If a mapping (with TMSI) was produced and passes dedup, emit
                    if mapping is not None:
                        imsi_val = mapping.get('imsi', '')
                        tmsi_val = mapping.get('tmsi', '')
                        if not tmsi_val:
                            continue
                        if dedup_enabled:
                            key = (imsi_val, tmsi_val)
                            if key in dedup_set:
                                continue
                            dedup_set.add(key)
                        # Push to UI/CSV queue
                        self.tmsi_ui_queue.put(mapping)

                # Done/EOF
                try:
                    await asyncio.wait_for(tshark_proc.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

            finally:
                # Remove proc from tracking and terminate if needed
                try:
                    if tshark_proc.returncode is None:
                        tshark_proc.terminate()
                        try:
                            await asyncio.wait_for(tshark_proc.wait(), timeout=0.5)
                        except asyncio.TimeoutError:
                            tshark_proc.kill()
                except Exception:
                    pass
                if tshark_proc in self._tmsi_procs:
                    self._tmsi_procs.remove(tshark_proc)

            if self.tmsi_stop_event.is_set():
                break

            # Unexpected exit; consider restart
            if restarts_left > 0:
                logger.warning("[TSHARK] Exited unexpectedly. Restarting...")
                restarts_left -= 1
                await asyncio.sleep(0.7)
                continue
            else:
                logger.error("[TSHARK] Exited unexpectedly. Restart attempts exhausted.")
                break

        # Cleanup: stop prune task and livemon readers
        await self._terminate_tmsi_async()

    def tmsi_handle_tshark_line(self, line, recent_imsi_by_chan, recent_imsi_by_cell, ttl_seconds):
        """
        Parse a tshark output line and update caches / produce IMSI→TMSI mapping dicts.

        Returns:
            mapping dict or None if the line didn't produce a (TMSI) mapping.
        """
        # Expected order:
        # 0: frame.time_epoch
        # 1: e212.imsi
        # 2: gsm_a.tmsi
        # 3: gsm_a.dtap.msg_mm_type
        # 4: gsm_a.lac
        # 5: gsm_a.rr.cell_id
        # 6: gsmtap.arfcn
        # 7: gsmtap.timeslot
        parts = line.split('\t')
        # Ensure list length
        while len(parts) < 8:
            parts.append('')

        def parse_num(val):
            """Parse decimal or 0x... hex into int; return None on failure/empty."""
            v = val.strip()
            if not v:
                return None
            try:
                if v.lower().startswith('0x'):
                    return int(v, 16)
                return int(v)
            except ValueError:
                # some fields might be like "0001" etc.; attempt int anyway
                try:
                    return int(v, 10)
                except Exception:
                    return None

        def norm_tmsi(val):
            """Normalize TMSI field to 8-hex uppercase without 0x; return '' if invalid/empty."""
            v = val.strip()
            if not v:
                return ''
            # tshark may output decimal or 0xXXXXXXXX
            # Try hex "0x...."
            if v.lower().startswith('0x'):
                t = v[2:].upper()
            else:
                # treat as int and then format
                try:
                    t = f"{int(v):08X}"
                except ValueError:
                    return ''
            # Filter invalid TMSI
            if t == "00000000" or t == "FFFFFFFF":
                return ''
            return t

        epoch_s = parts[0].strip()
        imsi = parts[1].strip()
        tmsi = norm_tmsi(parts[2])
        mm_type_raw = parts[3].strip().lower()
        lac = parse_num(parts[4])
        cell_id = parse_num(parts[5])
        arfcn = parse_num(parts[6])
        timeslot = parse_num(parts[7])

        # Determine timestamp
        try:
            ts_epoch = float(epoch_s) if epoch_s else time.time()
        except ValueError:
            ts_epoch = time.time()

        # Update IMSI caches on any line that carries IMSI (even without TMSI)
        if imsi:
            if arfcn is not None and timeslot is not None:
                recent_imsi_by_chan[(arfcn, timeslot)] = {
                    'imsi': imsi, 'ts_epoch': ts_epoch, 'lac': lac, 'cell_id': cell_id
                }
            if lac is not None and cell_id is not None:
                key = (lac, cell_id)
                arr = recent_imsi_by_cell.get(key, [])
                arr.append((ts_epoch, imsi))
                # keep last few by policy
                if len(arr) > 5:
                    arr = arr[-5:]
                recent_imsi_by_cell[key] = arr

        # Only produce mapping when we have TMSI and MM type indicates assignment
        if not tmsi:
            return None

        # mm_type can be "0x02" or "2" etc.
        mm_type = None
        if mm_type_raw:
            try:
                mm_type = int(mm_type_raw, 16) if mm_type_raw.startswith('0x') else int(mm_type_raw)
            except ValueError:
                mm_type = None

        if mm_type not in (0x02, 0x10):  # 0x02: Location Updating Accept, 0x10: TMSI Reallocation Command
            return None

        # Correlate IMSI for this TMSI line
        src_msg = "Location Updating Accept" if mm_type == 0x02 else "TMSI Reallocation Command"
        now = ts_epoch

        # Prefer (arfcn, timeslot) match
        imsi_match = ''
        if arfcn is not None and timeslot is not None:
            e = recent_imsi_by_chan.get((arfcn, timeslot))
            if e and (now - e['ts_epoch'] <= ttl_seconds):
                imsi_match = e['imsi']

        # Fallback to (lac, cell) with nearest time within TTL
        if not imsi_match and (lac is not None and cell_id is not None):
            arr = recent_imsi_by_cell.get((lac, cell_id), [])
            # pick the most recent within TTL
            arr_recent = [(ts, im) for (ts, im) in arr if now - ts <= ttl_seconds]
            if arr_recent:
                arr_recent.sort(key=lambda x: x[0], reverse=True)
                imsi_match = arr_recent[0][1]

        # Build mapping dict
        iso = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat()
        mapping = {
            'timestamp_iso': iso,
            'imsi': imsi_match,
            'tmsi': tmsi,
            'lac': '' if lac is None else str(lac),
            'cell_id': '' if cell_id is None else str(cell_id),
            'arfcn': '' if arfcn is None else str(arfcn),
            'timeslot': '' if timeslot is None else str(timeslot),
            'source_msg': src_msg
        }
        return mapping

    async def _reader_task(self, proc, prefix=''):
        """
        Generic async reader for a subprocess' stdout that forwards lines to the logger.
        """
        try:
            while not self.tmsi_stop_event.is_set():
                line = await proc.stdout.readline()
                if not line:
                    break
                s = line.decode(errors='replace').rstrip("\n")
                if s:
                    logger.info(f"{prefix} {s}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"{prefix} reader error: {e}")
        finally:
            try:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=0.5)
                    except asyncio.TimeoutError:
                        proc.kill()
            except Exception:
                pass
            if proc in self._tmsi_procs:
                self._tmsi_procs.remove(proc)

    # ------------------ TMSI UI update / CSV writing ------------------

    def _append_tmsi_text(self, text, bold=False):
        """Append text to the TMSI scrolled textbox safely."""
        self.tmsi_text.config(state='normal')
        if bold and "bold" not in self.tmsi_text.tag_names():
            self.tmsi_text.tag_config("bold", font=('Consolas', 9, 'bold'))
        if bold:
            start = self.tmsi_text.index(tk.END)
            self.tmsi_text.insert(tk.END, text)
            end = self.tmsi_text.index(tk.END)
            self.tmsi_text.tag_add("bold", start, end)
        else:
            self.tmsi_text.insert(tk.END, text)
        self.tmsi_text.see(tk.END)
        self.tmsi_text.config(state='disabled')

    def update_tmsi_display(self):
        """
        Drain the TMSI UI queue and update the text area & CSV.
        Runs periodically via root.after().
        """
        drained = 0
        while not self.tmsi_ui_queue.empty():
            mapping = self.tmsi_ui_queue.get()
            # Render line
            line = "{timestamp_iso}, {imsi}, {tmsi}, {lac}, {cell_id}, {arfcn}, {timeslot}, {source_msg}\n".format(
                **mapping
            )
            self._append_tmsi_text(line)

            # Write CSV row
            try:
                if self.tmsi_csv_handle:
                    self._tmsi_csv_writer.writerow([
                        mapping.get('timestamp_iso', ''),
                        mapping.get('imsi', ''),
                        mapping.get('tmsi', ''),
                        mapping.get('lac', ''),
                        mapping.get('cell_id', ''),
                        mapping.get('arfcn', ''),
                        mapping.get('timeslot', ''),
                        mapping.get('source_msg', '')
                    ])
                    self.tmsi_csv_handle.flush()
            except Exception as e:
                logger.error(f"[SCAN] CSV write error: {e}")

            drained += 1

        if drained:
            logger.info(f"[SCAN] Appended {drained} mapping(s) to CSV and UI.")

        self.root.after(100, self.update_tmsi_display)

    # ------------------ Window lifecycle ------------------

    def on_close(self):
        """Graceful shutdown for the entire app."""
        try:
            # Stop legacy IMSI scan
            self.stop_imsi_scan()
        except Exception:
            pass

        # Stop TMSI capture if running
        try:
            if self.tmsi_running:
                self.stop_tmsi_capture()
                # Give a short moment for tasks to end
                # (Do not block indefinitely; UI is closing)
                time_limit = time.time() + 3.0
                while time.time() < time_limit and self.tmsi_running:
                    self.root.update_idletasks()
                    time.sleep(0.05)
        except Exception:
            pass

        # Close CSV if still open
        try:
            if self.tmsi_csv_handle:
                self.tmsi_csv_handle.flush()
                self.tmsi_csv_handle.close()
        except Exception:
            pass

        # Shutdown asyncio loop
        try:
            # Ensure all TMSI async elements are terminated
            fut = asyncio.run_coroutine_threadsafe(self._terminate_tmsi_async(), self.async_loop)
            try:
                fut.result(timeout=1.0)
            except Exception:
                pass
            self.async_loop.call_soon_threadsafe(self.async_loop.stop)
        except Exception:
            pass

        logger.info("=== IMSI Scanner GUI Closed ===")
        self.root.destroy()


# ------------------ Main execution ------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = IMSIScannerGUI(root)

    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

