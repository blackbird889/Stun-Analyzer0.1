import tkinter as tk
from tkinter import filedialog, messagebox
import pyshark
import re
from collections import Counter
import requests
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class StunPacketExtractor:
    def __init__(self, master):
        self.master = master
        master.title("STUN Packet Extractor")

        # Main frame
        self.main_frame = tk.Frame(master, padx=20, pady=20, bg="lightgray")
        self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Input file selection
        self.input_file_label = tk.Label(self.main_frame, text="Input PCAP file:", font=("Arial", 12), bg="lightgray")
        self.input_file_label.pack(pady=5)
        self.input_file_path = tk.StringVar()
        self.browse_input_button = tk.Button(self.main_frame, text="Browse Input File", command=self.browse_input_file, bg="blue", fg="white")
        self.browse_input_button.pack(pady=5)

        # Output file selection
        self.output_file_label = tk.Label(self.main_frame, text="Output file:", font=("Arial", 12), bg="lightgray")
        self.output_file_label.pack(pady=5)
        self.output_file_path = tk.StringVar()
        self.output_file_browse_button = tk.Button(self.main_frame, text="Browse Output File", command=self.browse_output_file, bg="blue", fg="white")
        self.output_file_browse_button.pack(pady=5)

        # Extract, Locate IPs, and Count Packets buttons
        self.extract_button = tk.Button(self.main_frame, text="Extract STUN Packets", command=self.extract_packets, bg="green", fg="white")
        self.extract_button.pack(pady=10)
        self.locate_ips_button = tk.Button(self.main_frame, text="Locate IPs in Final Text", command=self.locate_ips, bg="orange", fg="white")
        self.locate_ips_button.pack(pady=10)
        self.count_packets_button = tk.Button(self.main_frame, text="Count STUN Packets", command=self.count_packets, bg="purple", fg="white")
        self.count_packets_button.pack(pady=10)

        # Signature label
        self.signature_label = tk.Label(master, text="Created by Moataz Younes", bg="lightgray", font=("Arial", 10, "italic"))
        self.signature_label.pack(side=tk.BOTTOM, pady=10)

    def browse_input_file(self):
        """Open a dialog to select the input PCAP file and store the path."""
        file_path = filedialog.askopenfilename(title="Select PCAP file", filetypes=[("PCAP files", "*.pcapng *.pcap")])
        if file_path:
            self.input_file_path.set(file_path)

    def browse_output_file(self):
        """Open a dialog to select the output file location and store the path."""
        file_path = filedialog.asksaveasfilename(title="Select output file", filetypes=[("Text files", "*.txt")], defaultextension=".txt")
        if file_path:
            self.output_file_path.set(file_path)

    def load_capture_file(self, file_path):
        """Load the PCAP file for analysis."""
        try:
            logging.debug(f"Attempting to load file: {file_path}")
            cap = pyshark.FileCapture(file_path, display_filter='stun')
            logging.debug("Capture file loaded successfully")
            return cap
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            messagebox.showerror("Error", f"File not found: {file_path}")
        except pyshark.capture.capture.TSharkNotFoundException:
            logging.error("TShark not found. Make sure it is installed and accessible.")
            messagebox.showerror("Error", "TShark not found. Make sure it is installed and accessible.")
        except Exception as e:
            logging.error(f"Failed to load capture file: {str(e)}")
            messagebox.showerror("Error", f"Failed to load capture file: {str(e)}")
        return None

    def extract_stun_packets(self, cap):
        """Extract STUN packets with IP and timestamp details."""
        packets = []
        try:
            for packet in cap:
                if hasattr(packet, 'ip') and hasattr(packet, 'udp'):
                    dest_ip = packet.ip.dst
                    dest_port = packet.udp.dstport
                    timestamp = packet.sniff_time
                    packets.append((dest_ip, dest_port, timestamp))
        except Exception as e:
            logging.error(f"Error while extracting packets: {str(e)}")
        finally:
            cap.close()
        return packets

    def identify_father_ip(self, packets):
        """Identify the 'father' IP address based on specific criteria."""
        ip_counter = Counter([packet[0] for packet in packets])  # Counting destination IPs
        if ip_counter:
            father_ip, _ = ip_counter.most_common(1)[0]
            return father_ip
        return None

    def get_ip_geolocation(self, ip_address):
        """Fetch the geolocation and ISP for a given IP address using an API."""
        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            data = response.json()
            return data.get('city', 'Unknown City'), data.get('region', 'Unknown Region'), data.get('country', 'Unknown Country'), data.get('org', 'Unknown ISP')
        except Exception as e:
            logging.error(f"Error fetching geolocation for IP {ip_address}: {str(e)}")
            return 'Unknown City', 'Unknown Region', 'Unknown Country', 'Unknown ISP'

    def write_packets_to_file(self, file_path, packets, father_ip):
        """Write extracted STUN packet details to a file, highlighting the 'father' IP."""
        try:
            with open(file_path, 'w') as f:
                for packet in packets:
                    dest_ip = packet[0]
                    dest_port = packet[1]
                    timestamp = packet[2]

                    city, region, country, isp = self.get_ip_geolocation(dest_ip)
                    f.write(f"STUN Packet:\n")
                    if dest_ip == father_ip:
                        f.write(f"  Destination IP (Father): {dest_ip}\n")
                    else:
                        f.write(f"  Destination IP: {dest_ip}\n")
                    f.write(f"  Location: {city}, {region}, {country}\n")
                    f.write(f"  ISP: {isp}\n")
                    f.write(f"  Destination Port: {dest_port}\n")
                    f.write(f"  Date and Time: {timestamp}\n\n")
            messagebox.showinfo("Success", "STUN packets extracted successfully.")
        except Exception as e:
            logging.error(f"Failed to write to file: {str(e)}")
            messagebox.showerror("Error", f"Failed to write to file: {str(e)}")

    def locate_ips(self):
        """Locate and display IP addresses from the output file."""
        output_file_path = self.output_file_path.get()
        if not output_file_path:
            messagebox.showerror("Error", "Please select an output file path")
            return

        try:
            with open(output_file_path, 'r') as f:
                text = f.read()
                ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
                if ip_addresses:
                    ip_addresses_str = ', '.join(ip_addresses)
                    messagebox.showinfo("IP Addresses", f"IP Addresses found: {ip_addresses_str}")
                else:
                    messagebox.showinfo("IP Addresses", "No IP addresses found in the final text.")
        except Exception as e:
            logging.error(f"Failed to locate IPs: {str(e)}")
            messagebox.showerror("Error", f"Failed to locate IPs: {str(e)}")

    def extract_packets(self):
        """Extract STUN packets from the input PCAP file and write to the output file."""
        input_file_path = self.input_file_path.get()
        output_file_path = self.output_file_path.get()

        if not input_file_path:
            messagebox.showerror("Error", "Please select an input file")
            return

        if not output_file_path:
            messagebox.showerror("Error", "Please select an output file path")
            return

        cap = self.load_capture_file(input_file_path)
        if cap is None:
            return

        packets = self.extract_stun_packets(cap)
        if packets:
            father_ip = self.identify_father_ip(packets)
            self.write_packets_to_file(output_file_path, packets, father_ip)
        else:
            messagebox.showinfo("No Packets", "No STUN packets found in the capture file.")

    def count_packets(self):
        """Count the number of STUN packets in the output file."""
        output_file_path = self.output_file_path.get()
        if not output_file_path:
            messagebox.showerror("Error", "Please select an output file path")
            return

        try:
            with open(output_file_path, 'r') as f:
                text = f.read()
                # Count the number of "STUN Packet:" occurrences
                count = text.count("STUN Packet:")
                messagebox.showinfo("Packet Count", f"Number of STUN packets: {count}")
        except Exception as e:
            logging.error(f"Failed to count packets: {str(e)}")
            messagebox.showerror("Error", f"Failed to count packets: {str(e)}")

# Initialize and run the GUI
root = tk.Tk()
app = StunPacketExtractor(root)
root.mainloop()
