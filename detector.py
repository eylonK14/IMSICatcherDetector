#!/usr/bin/env python3
"""
Marlin IMSI Catcher Detection System
Based on the paper "Detecting IMSI-Catchers by Characterizing Identity Exposing Messages"
This implementation detects IMSI catchers by monitoring the ratio of IMSI-exposing connections
"""

import os
import sys
import time
import subprocess
import sqlite3
import json
import numpy as np
from datetime import datetime
from collections import defaultdict
import signal
import threading
from scipy import stats
import pyshark
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IMSIExposingMessage:
    """Class to define IMSI-exposing messages based on 3GPP standards"""
    
    # Message types that expose IMSI as identified in the paper (Table III)
    GSM_MESSAGES = {
        'identity_request': {'filter': 'gsm_a.dtap.msg_mm_type == 0x18'},
        'auth_reject': {'filter': 'gsm_a.dtap.msg_mm_type == 0x11'},
        'abort_cause_6': {'filter': 'gsm_a.dtap.msg_mm_type == 0x29 && gsm_a.dtap.rej_cause == 6'},
        'loc_update_reject': {'filter': 'gsm_a.dtap.msg_mm_type == 0x04 && (gsm_a.dtap.rej_cause == 2 || gsm_a.dtap.rej_cause == 3 || gsm_a.dtap.rej_cause == 6 || gsm_a.dtap.rej_cause == 11 || gsm_a.dtap.rej_cause == 12 || gsm_a.dtap.rej_cause == 13)'},
        'cm_service_reject': {'filter': 'gsm_a.dtap.msg_mm_type == 0x22 && (gsm_a.dtap.rej_cause == 4 || gsm_a.dtap.rej_cause == 6)'}
    }
    
    UMTS_MESSAGES = {
        'identity_request': {'filter': 'nas_eps.nas_msg_emm_type == 0x55'},
        'auth_reject': {'filter': 'nas_eps.nas_msg_emm_type == 0x54'},
        'attach_reject': {'filter': 'nas_eps.nas_msg_emm_type == 0x44 && (nas_eps.emm_cause == 3 || nas_eps.emm_cause == 6 || nas_eps.emm_cause == 7 || nas_eps.emm_cause == 8 || (nas_eps.emm_cause >= 11 && nas_eps.emm_cause <= 15))'},
        'detach_request': {'filter': 'nas_eps.nas_msg_emm_type == 0x45 && nas_eps.emm_detach_type_ul == 0 && (nas_eps.emm_cause == 2 || nas_eps.emm_cause == 3 || nas_eps.emm_cause == 6 || nas_eps.emm_cause == 7 || nas_eps.emm_cause == 8 || (nas_eps.emm_cause >= 11 && nas_eps.emm_cause <= 15))'},
        'tau_reject': {'filter': 'nas_eps.nas_msg_emm_type == 0x4b && (nas_eps.emm_cause == 3 || nas_eps.emm_cause == 6 || nas_eps.emm_cause == 7 || nas_eps.emm_cause == 9 || nas_eps.emm_cause == 11 || nas_eps.emm_cause == 12 || nas_eps.emm_cause == 14)'},
        'service_reject': {'filter': 'nas_eps.nas_msg_emm_type == 0x4e && (nas_eps.emm_cause == 3 || nas_eps.emm_cause == 6 || nas_eps.emm_cause == 7 || nas_eps.emm_cause == 9 || nas_eps.emm_cause == 11 || nas_eps.emm_cause == 12)'}
    }
    
    LTE_MESSAGES = UMTS_MESSAGES  # LTE uses same NAS messages as UMTS
    
    @classmethod
    def get_filters_for_generation(cls, generation):
        """Get Wireshark display filters for a specific generation"""
        if generation == '2G':
            return cls.GSM_MESSAGES
        elif generation == '3G':
            return cls.UMTS_MESSAGES
        elif generation == '4G' or generation == 'LTE':
            return cls.LTE_MESSAGES
        else:
            return {}

class MarlinDetector:
    """Main detection system implementing the Marlin methodology"""
    
    def __init__(self, db_path="marlin_data.db", threshold_multiplier=10):
        self.db_path = db_path
        self.threshold_multiplier = threshold_multiplier  # For anomaly detection
        self.running = True
        self.init_database()
        self.baseline_ratios = self.load_baseline_data()
        
    def init_database(self):
        """Initialize SQLite database for storing detection data"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create tables for storing capture data
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                frequency INTEGER,
                generation TEXT,
                duration_seconds INTEGER,
                total_connections INTEGER,
                imsi_exposing_connections INTEGER,
                ie_ratio REAL,
                location TEXT,
                notes TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT,
                generation TEXT,
                location_type TEXT,
                median_ie_ratio REAL,
                max_ie_ratio REAL,
                samples INTEGER
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                frequency INTEGER,
                generation TEXT,
                ie_ratio REAL,
                baseline_median REAL,
                p_value REAL,
                severity TEXT,
                message_types TEXT
            )
        ''')
        
        self.conn.commit()
        
    def load_baseline_data(self):
        """Load baseline IE ratios from database"""
        self.cursor.execute('SELECT generation, median_ie_ratio, max_ie_ratio FROM baseline_data')
        baselines = {}
        for row in self.cursor.fetchall():
            generation, median_ratio, max_ratio = row
            baselines[generation] = {
                'median': median_ratio,
                'max': max_ratio
            }
        
        # Default baselines from the paper if no data exists
        if not baselines:
            baselines = {
                'LTE': {'median': 0.03, 'max': 0.10},  # 3% median, 10% max from paper
                'GSM': {'median': 0.06, 'max': 0.15},  # 6% median from paper
                'UMTS': {'median': 0.03, 'max': 0.10}  # Assumed similar to LTE
            }
            # Store defaults
            for gen, values in baselines.items():
                self.cursor.execute('''
                    INSERT INTO baseline_data (provider, generation, location_type, median_ie_ratio, max_ie_ratio, samples)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('default', gen, 'mixed', values['median'], values['max'], 0))
            self.conn.commit()
            
        return baselines
    
    def capture_traffic(self, frequency, duration_seconds=60, sdr_device='usrp'):
        """Capture cellular traffic on specified frequency"""
        capture_file = f'capture_{frequency}_{int(time.time())}.pcap'
        
        if sdr_device == 'usrp':
            # Using gr-gsm for GSM or LTESniffer for LTE
            # This is a simplified version - actual implementation would use proper SDR tools
            cmd = [
                'timeout', str(duration_seconds),
                'tshark', '-i', 'lo',  # Replace with actual SDR interface
                '-w', capture_file,
                '-f', f'port {frequency}'  # Simplified filter
            ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return capture_file
        except subprocess.CalledProcessError as e:
            logging.error(f"Capture failed: {e}")
            return None
    
    def analyze_capture(self, capture_file, generation='LTE'):
        """Analyze packet capture for IMSI-exposing messages"""
        try:
            # Get appropriate filters for the generation
            message_filters = IMSIExposingMessage.get_filters_for_generation(generation)
            
            total_connections = 0
            imsi_exposing_connections = 0
            message_types_found = defaultdict(int)
            
            # Open capture file with pyshark
            cap = pyshark.FileCapture(capture_file)
            
            # Track connections (simplified - actual implementation would track by C-RNTI/TMSI)
            connections = defaultdict(lambda: {'has_imsi_expose': False, 'messages': []})
            
            # First pass: identify all connections
            for packet in cap:
                # Simplified connection tracking
                if hasattr(packet, 'rrc') and hasattr(packet.rrc, 'rrcconnectionrequest'):
                    conn_id = f"{packet.frame_info.time_epoch}"
                    connections[conn_id]['start'] = True
            
            # Reset capture for second pass
            cap.close()
            cap = pyshark.FileCapture(capture_file)
            
            # Second pass: check for IMSI-exposing messages
            for packet in cap:
                # Check each message type
                for msg_type, filter_info in message_filters.items():
                    try:
                        # Apply display filter
                        if self._packet_matches_filter(packet, filter_info['filter']):
                            # Find associated connection
                            conn_id = self._find_connection_id(packet, connections)
                            if conn_id:
                                connections[conn_id]['has_imsi_expose'] = True
                                connections[conn_id]['messages'].append(msg_type)
                                message_types_found[msg_type] += 1
                    except:
                        continue
            
            cap.close()
            
            # Calculate statistics
            total_connections = len(connections)
            imsi_exposing_connections = sum(1 for c in connections.values() if c['has_imsi_expose'])
            
            ie_ratio = imsi_exposing_connections / total_connections if total_connections > 0 else 0
            
            return {
                'total_connections': total_connections,
                'imsi_exposing_connections': imsi_exposing_connections,
                'ie_ratio': ie_ratio,
                'message_types': dict(message_types_found)
            }
            
        except Exception as e:
            logging.error(f"Analysis failed: {e}")
            return None
    
    def _packet_matches_filter(self, packet, filter_str):
        """Check if packet matches Wireshark display filter (simplified)"""
        # This is a simplified version - actual implementation would properly parse filters
        # For demonstration, we'll do basic field checking
        parts = filter_str.split(' && ')
        for part in parts:
            if '==' in part:
                field, value = part.split(' == ')
                field = field.strip()
                value = value.strip()
                
                # Navigate packet structure to find field
                try:
                    field_parts = field.split('.')
                    obj = packet
                    for fp in field_parts:
                        obj = getattr(obj, fp)
                    
                    if str(obj) != value:
                        return False
                except:
                    return False
            elif '||' in part:
                # Handle OR conditions
                sub_parts = part.split(' || ')
                any_match = False
                for sp in sub_parts:
                    if self._packet_matches_filter(packet, sp):
                        any_match = True
                        break
                if not any_match:
                    return False
        
        return True
    
    def _find_connection_id(self, packet, connections):
        """Find which connection a packet belongs to (simplified)"""
        # In real implementation, would match by C-RNTI, TMSI, etc.
        packet_time = float(packet.frame_info.time_epoch)
        
        # Find closest connection start time
        best_match = None
        min_diff = float('inf')
        
        for conn_id, conn_data in connections.items():
            conn_time = float(conn_id)
            if conn_time <= packet_time:
                diff = packet_time - conn_time
                if diff < min_diff and diff < 10:  # Within 10 seconds
                    min_diff = diff
                    best_match = conn_id
        
        return best_match
    
    def detect_anomalies(self, analysis_results, generation='LTE'):
        """Detect if IE ratio is anomalous compared to baseline"""
        if not analysis_results:
            return None
        
        ie_ratio = analysis_results['ie_ratio']
        baseline = self.baseline_ratios.get(generation, self.baseline_ratios.get('LTE'))
        
        # Detection criteria from the paper
        anomaly_detected = False
        severity = 'LOW'
        
        # Check against baseline
        if ie_ratio > baseline['median'] * self.threshold_multiplier:
            anomaly_detected = True
            severity = 'HIGH'
        elif ie_ratio > baseline['max']:
            anomaly_detected = True
            severity = 'MEDIUM'
        
        # Statistical test (simplified Mann-Whitney U test simulation)
        # In real implementation, would compare against baseline distribution
        p_value = self._calculate_p_value(ie_ratio, baseline['median'])
        
        if p_value < 0.005:  # Paper uses p << 0.005
            anomaly_detected = True
            if severity != 'HIGH':
                severity = 'MEDIUM'
        
        if anomaly_detected:
            return {
                'detected': True,
                'ie_ratio': ie_ratio,
                'baseline_median': baseline['median'],
                'p_value': p_value,
                'severity': severity,
                'message_types': analysis_results['message_types']
            }
        
        return None
    
    def _calculate_p_value(self, observed_ratio, baseline_median):
        """Calculate p-value for statistical significance (simplified)"""
        # In real implementation, would use actual baseline distribution
        # For now, simulate with normal distribution around baseline
        baseline_std = baseline_median * 0.2  # Assume 20% standard deviation
        
        # One-sided test (is observed significantly higher than baseline?)
        z_score = (observed_ratio - baseline_median) / baseline_std
        p_value = 1 - stats.norm.cdf(z_score)
        
        return p_value
    
    def monitor_frequencies(self, frequencies, generation='LTE', duration_per_freq=60):
        """Main monitoring loop cycling through frequencies"""
        logging.info(f"Starting Marlin IMSI Catcher Detection")
        logging.info(f"Monitoring {len(frequencies)} frequencies, {duration_per_freq}s each")
        logging.info(f"Baseline IE ratio for {generation}: {self.baseline_ratios.get(generation, {}).get('median', 0)*100:.1f}%")
        logging.info("Press Ctrl+C to stop\n")
        
        freq_index = 0
        
        while self.running:
            try:
                frequency = frequencies[freq_index % len(frequencies)]
                logging.info(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring frequency {frequency}")
                
                # Capture traffic
                capture_file = self.capture_traffic(frequency, duration_per_freq)
                
                if capture_file and os.path.exists(capture_file):
                    # Analyze capture
                    results = self.analyze_capture(capture_file, generation)
                    
                    if results:
                        # Store results
                        self.cursor.execute('''
                            INSERT INTO captures 
                            (timestamp, frequency, generation, duration_seconds, total_connections, 
                             imsi_exposing_connections, ie_ratio, location, notes)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (datetime.now(), frequency, generation, duration_per_freq,
                              results['total_connections'], results['imsi_exposing_connections'],
                              results['ie_ratio'], 'monitoring', ''))
                        self.conn.commit()
                        
                        # Check for anomalies
                        anomaly = self.detect_anomalies(results, generation)
                        
                        if anomaly:
                            logging.warning(f"\n[!] ANOMALY DETECTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            logging.warning(f"    Frequency: {frequency}")
                            logging.warning(f"    IE Ratio: {anomaly['ie_ratio']*100:.1f}% (baseline: {anomaly['baseline_median']*100:.1f}%)")
                            logging.warning(f"    Severity: {anomaly['severity']}")
                            logging.warning(f"    P-value: {anomaly['p_value']:.6f}")
                            logging.warning(f"    Message types: {anomaly['message_types']}")
                            
                            # Store detection
                            self.cursor.execute('''
                                INSERT INTO detections
                                (timestamp, frequency, generation, ie_ratio, baseline_median, 
                                 p_value, severity, message_types)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (datetime.now(), frequency, generation, anomaly['ie_ratio'],
                                  anomaly['baseline_median'], anomaly['p_value'], 
                                  anomaly['severity'], json.dumps(anomaly['message_types'])))
                            self.conn.commit()
                        else:
                            logging.info(f"    IE Ratio: {results['ie_ratio']*100:.1f}% - Normal")
                    
                    # Clean up capture file
                    os.remove(capture_file)
                
                # Move to next frequency
                freq_index += 1
                
                # Short pause between frequencies
                time.sleep(1)
                
            except KeyboardInterrupt:
                logging.info("\nStopping detection...")
                self.running = False
                break
            except Exception as e:
                logging.error(f"Error during monitoring: {e}")
                freq_index += 1
                time.sleep(5)
    
    def generate_report(self):
        """Generate detection report"""
        print("\n=== MARLIN IMSI CATCHER DETECTION REPORT ===")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Get recent detections
        self.cursor.execute('''
            SELECT timestamp, frequency, generation, ie_ratio, severity, message_types
            FROM detections
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        
        detections = self.cursor.fetchall()
        
        if detections:
            print("Recent Anomaly Detections:")
            print("-" * 80)
            for detection in detections:
                timestamp, freq, gen, ratio, severity, msg_types = detection
                print(f"[{timestamp}] Freq: {freq} ({gen})")
                print(f"  IE Ratio: {ratio*100:.1f}% | Severity: {severity}")
                print(f"  Messages: {msg_types}\n")
        else:
            print("No anomalies detected.")
        
        # Summary statistics
        self.cursor.execute('''
            SELECT COUNT(*), AVG(ie_ratio), MAX(ie_ratio)
            FROM captures
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        
        count, avg_ratio, max_ratio = self.cursor.fetchone()
        
        if count:
            print(f"\nLast 24 Hours Statistics:")
            print(f"  Total captures: {count}")
            print(f"  Average IE ratio: {(avg_ratio or 0)*100:.2f}%")
            print(f"  Maximum IE ratio: {(max_ratio or 0)*100:.2f}%")
        
        self.cursor.execute('SELECT COUNT(*) FROM detections')
        total_detections = self.cursor.fetchone()[0]
        
        print(f"\nTotal anomalies detected: {total_detections}")
    
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'conn'):
            self.conn.close()


class FrequencyScanner:
    """Helper class to find active cellular frequencies"""
    
    @staticmethod
    def get_common_frequencies(provider='generic', generation='LTE'):
        """Get common frequencies for providers"""
        # Common LTE frequencies (EARFCNs) in the US
        common_lte = {
            'att': [700, 2300, 5780, 9820],  # Bands 12, 2, 5, 30
            'verizon': [750, 2050, 5230],    # Bands 13, 4, 2
            'tmobile': [800, 2000, 9880],    # Bands 12, 4, 71
            'generic': [700, 750, 800, 2000, 2050, 2300, 5230, 5780, 9820, 9880]
        }
        
        # Common GSM frequencies
        common_gsm = {
            'generic': [128, 251, 512, 661, 836]  # GSM 850/1900
        }
        
        if generation == 'LTE':
            return common_lte.get(provider.lower(), common_lte['generic'])
        elif generation == 'GSM' or generation == '2G':
            return common_gsm.get(provider.lower(), common_gsm['generic'])
        else:
            return common_lte['generic']  # Default to LTE


def main():
    """Main function to run Marlin detector"""
    detector = MarlinDetector()
    
    # Set up signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print("\nShutting down...")
        detector.running = False
        detector.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Get frequencies to monitor
    frequencies = FrequencyScanner.get_common_frequencies('generic', 'LTE')
    
    # Start monitoring
    try:
        detector.monitor_frequencies(frequencies, generation='LTE', duration_per_freq=60)
    finally:
        detector.generate_report()
        detector.cleanup()


if __name__ == "__main__":
    main()