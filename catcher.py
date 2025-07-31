#!/usr/bin/env python3
"""
IMSI Catcher Simulator for Marlin Detection System
Generates cellular traffic with abnormal IMSI-exposing message ratios
"""

import os
import sys
import time
import random
import logging
import argparse
from scapy.all import *
from scapy.layers.inet import IP, UDP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IMSICatcherSimulator:
    """Simulates an IMSI catcher by generating abnormal IMSI-exposing traffic"""
    
    def __init__(self, output_file="imsi_catcher_traffic.pcap", 
                 ie_ratio=0.5, duration=60, generation="LTE"):
        """
        Initialize simulator
        :param output_file: Output PCAP filename
        :param ie_ratio: Ratio of IMSI-exposing connections (0.0-1.0)
        :param duration: Duration of simulation in seconds
        :param generation: Cellular generation (LTE, GSM, UMTS)
        """
        self.output_file = output_file
        self.ie_ratio = ie_ratio
        self.duration = duration
        self.generation = generation
        self.base_time = time.time()
        self.packets = []
        
        # Message type mappings
        self.message_types = {
            "LTE": {
                "identity_request": b'\x07\x00\x55',  # NAS-EPS: EMM Identity Request
                "auth_reject": b'\x07\x00\x54',        # NAS-EPS: EMM Authentication Reject
                "attach_reject": b'\x07\x00\x44'       # NAS-EPS: EMM Attach Reject
            },
            "GSM": {
                "identity_request": b'\x18',           # MM: Identity Request
                "auth_reject": b'\x11',                # MM: Authentication Reject
                "loc_update_reject": b'\x04'           # MM: Location Updating Reject
            },
            "UMTS": {
                "identity_request": b'\x07\x00\x55',   # Same as LTE
                "attach_reject": b'\x07\x00\x44'       # Same as LTE
            }
        }
        
        # Frequency mappings
        self.frequencies = {
            "LTE": [700, 750, 800, 850, 900, 1500, 1700, 1800, 1900, 2100, 2300, 2500, 2600],
            "GSM": [128, 251, 512, 661, 836],
            "UMTS": [900, 2100]
        }
    
    def generate_normal_traffic(self, timestamp):
        """Generate normal cellular traffic patterns"""
        # Simulate connection setup
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                             random.randint(0, 255), random.randint(0, 255))
        dst_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                             random.randint(0, 255), random.randint(0, 255))
        
        # Create dummy cellular protocol payload
        payload = b'\x00' * 20  # Placeholder for normal traffic
        
        packet = Ether(src=src_mac, dst=dst_mac)/IP()/UDP(sport=12345, dport=12345)/payload
        packet.time = timestamp
        return packet
    
    def generate_imsi_exposing_message(self, timestamp):
        """Generate IMSI-exposing message based on generation type"""
        # Select random message type for this connection
        msg_type = random.choice(list(self.message_types[self.generation].keys()))
        payload = self.message_types[self.generation][msg_type]
        
        # Create packet with cellular-like characteristics
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                             random.randint(0, 255), random.randint(0, 255))
        dst_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                             random.randint(0, 255), random.randint(0, 255))
        
        # Add abnormal characteristics:
        # 1. Higher than normal frequency changes
        # 2. Suspicious timing patterns
        # 3. Abnormal message sequences
        packet = Ether(src=src_mac, dst=dst_mac)/IP()/UDP(sport=12345, dport=12345)/payload
        packet.time = timestamp
        return packet, msg_type
    
    def simulate(self):
        """Run the simulation and generate PCAP file"""
        logging.info(f"Starting IMSI catcher simulation ({self.duration}s)")
        logging.info(f"Target IE ratio: {self.ie_ratio*100:.1f}% | Generation: {self.generation}")
        
        connection_count = 0
        start_time = time.time()
        
        while (time.time() - start_time) < self.duration:
            # Simulate connection every 0.1-0.5 seconds
            time.sleep(random.uniform(0.1, 0.5))
            connection_count += 1
            
            # Create connection start
            conn_start_time = time.time()
            self.packets.append(self.generate_normal_traffic(conn_start_time))
            
            # Determine if this connection should expose IMSI
            if random.random() < self.ie_ratio:
                # Add abnormal delay before IMSI request
                time.sleep(random.uniform(0.01, 0.1))
                
                # Generate IMSI-exposing message
                expose_time = conn_start_time + random.uniform(0.1, 0.3)
                expose_packet, msg_type = self.generate_imsi_exposing_message(expose_time)
                self.packets.append(expose_packet)
                
                # Occasionally add multiple IMSI requests (characteristic of catchers)
                if random.random() < 0.3:  # 30% chance
                    for _ in range(random.randint(1, 3)):
                        additional_time = expose_time + random.uniform(0.05, 0.15)
                        additional_packet, _ = self.generate_imsi_exposing_message(additional_time)
                        self.packets.append(additional_packet)
        
        # Write all packets to PCAP file
        wrpcap(self.output_file, self.packets)
        logging.info(f"Simulation complete. Generated {connection_count} connections")
        logging.info(f"Output file: {self.output_file}")
        
        return self.output_file

def main():
    parser = argparse.ArgumentParser(description="IMSI Catcher Traffic Simulator")
    parser.add_argument("-o", "--output", default="imsi_catcher_traffic.pcap", 
                        help="Output PCAP filename")
    parser.add_argument("-r", "--ratio", type=float, default=0.5, 
                        help="Ratio of IMSI-exposing connections (0.0-1.0)")
    parser.add_argument("-d", "--duration", type=int, default=60, 
                        help="Simulation duration in seconds")
    parser.add_argument("-g", "--generation", default="LTE", 
                        choices=["LTE", "GSM", "UMTS"], help="Cellular generation")
    
    args = parser.parse_args()
    
    # Validate ratio
    if not 0.0 <= args.ratio <= 1.0:
        logging.error("Ratio must be between 0.0 and 1.0")
        sys.exit(1)
    
    simulator = IMSICatcherSimulator(
        output_file=args.output,
        ie_ratio=args.ratio,
        duration=args.duration,
        generation=args.generation
    )
    
    simulator.simulate()

if __name__ == "__main__":
    main()