import tkinter as tk
from tkinter import ttk
import psutil
import socket
import requests
import subprocess
import re
import pandas as pd

# Constants for anomaly detection
CPU_THRESHOLD = 80  # CPU usage threshold (percentage)
MEMORY_THRESHOLD = 80  # Memory usage threshold (percentage)
DISK_THRESHOLD = 80  # Disk usage threshold (percentage)
NETWORK_THRESHOLD = 1024 * 1024 * 10  # Network threshold (bytes) - 10 MB/s

# Load the CSV file into a DataFrame
csv_file = "C:/Users/adity/Downloads/List_of_TCP_and_UDP_port_numbers_2.csv"
df = pd.read_csv(csv_file)

# Create tkinter window
root = tk.Tk()
root.title("System Performance and IP Details")

# Define performance label
performance_label = ttk.Label(root, text="", wraplength=200)
performance_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

# Function to check CPU usage
def check_cpu_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    return cpu_percent

# Function to check memory usage
def check_memory_usage():
    mem = psutil.virtual_memory()
    return mem.percent

# Function to check disk usage
def check_disk_usage():
    disk = psutil.disk_usage('/')
    return disk.percent

# Function to check network usage
def check_network_usage():
    net = psutil.net_io_counters()
    return net.bytes_sent + net.bytes_recv

# Function to convert bytes to a human-readable format
def convert_bytes_to_readable(bytes):
    if bytes < 1024:
        return f"{bytes} bytes"
    elif bytes < 1024 * 1024:
        return f"{bytes / 1024:.2f} KB"
    elif bytes < 1024 * 1024 * 1024:
        return f"{bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes / (1024 * 1024 * 1024):.2f} GB"

# Function to display performance details
def display_performance():
    cpu_percent = check_cpu_usage()
    memory_percent = check_memory_usage()
    disk_percent = check_disk_usage()
    network_bytes = check_network_usage()

    performance_details = (
        f"CPU Usage: {cpu_percent}%\n"
        f"Memory Usage: {memory_percent}%\n"
        f"Disk Usage: {disk_percent}%\n"
        f"Network Usage: {convert_bytes_to_readable(network_bytes)}"
    )

    performance_label.config(text=performance_details)
    performance_button.config(state=tk.DISABLED)
    back_button.config(state=tk.NORMAL)

    # Schedule the next update
    performance_label.after(1000, display_performance)

# Function to hide performance details
def hide_performance():
    performance_label.config(text="")
    performance_button.config(state=tk.NORMAL)
    back_button.config(state=tk.DISABLED)

# Function to scan available network connections
def scan_connections():
    connections = psutil.net_connections(kind='inet')

    connection_details = ""
    threat_details = ""  # Initialize threat details
    
    for conn in connections:
        connection_details += f"Type: {'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'}\n"
        connection_details += f"Family: {'IPv4' if conn.family == socket.AF_INET else 'IPv6'}\n"
        connection_details += f"Local Address: {conn.laddr[0]}:{conn.laddr[1]}\n"
        connection_details += f"Local Port: {conn.laddr[1]}\n"

        # Check if the local port number has 'Unofficial' in the corresponding row
        if conn.laddr[1] in df['Port'].values and 'Unofficial' in df[df['Port'] == conn.laddr[1]].iloc[:, 1:].values:
            # Include additional details for the connection
            connection_details += f"Details: Unofficial\n"
            threat_details += connection_details  # Append to threat details
        
        # Check if remote address exists
        if conn.raddr:
            connection_details += f"Remote Address: {conn.raddr[0]}:{conn.raddr[1]}\n"
            connection_details += f"Remote Port: {conn.raddr[1]}\n"
        else:
            connection_details += "Remote Address: N/A\n"
            connection_details += "Remote Port: N/A\n"
            
        # Get process associated with the connection
        process_name = "N/A"
        if conn.pid:
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
            except psutil.NoSuchProcess:
                pass
                
        connection_details += f"Process: {process_name}\n"
        connection_details += f"Status: {'ESTABLISHED' if conn.status == psutil.CONN_ESTABLISHED else 'LISTENING' if conn.status == psutil.CONN_LISTEN else 'UNKNOWN'}\n"
        connection_details += f"PID: {conn.pid}\n"
        connection_details += "\n"

    connections_text.delete('1.0', tk.END)
    connections_text.insert(tk.END, connection_details)
    
    threat_text.delete('1.0', tk.END)  # Clear previous threat details
    
    if threat_details:
        threat_text.insert(tk.END, threat_details)  # Display threat details
    else:
        threat_text.insert(tk.END, "NO UNOFFICIAL PORT DETECTED")  # Display message if no threat detected

# Function to get IP location details
def get_ip_details():
    ip_address = ip_entry.get()
    url = f"http://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    location = data.get("loc", None)
    country = data.get("country", None)
    city = data.get("city", None)
    region = data.get("region", None)
    isp = data.get("org", None)
    postal = data.get("postal", None)
    dns = data.get("rdns", None)

    ip_details = ""
    if location:
        latitude, longitude = location.split(',')
        ip_details += f"Latitude: {latitude}, Longitude: {longitude}\n"
        ip_details += f"Country: {country}\n" if country else "Country not found\n"
        ip_details += f"City: {city}\n" if city else "City not found\n"
        ip_details += f"Region: {region}\n" if region else "Region not found\n"
        ip_details += f"ISP: {isp}\n" if isp else "ISP not found\n"
        ip_details += f"Postal Code: {postal}\n" if postal else "Postal Code not found\n"
        ip_details += f"Reverse DNS: {dns}\n" if dns else "Reverse DNS not found\n"
    else:
        ip_details += "Location not found\n"

    ip_details_text.delete('1.0', tk.END)
    ip_details_text.insert(tk.END, ip_details)

# Function to retrieve Wi-Fi network information and connected devices
def scan_wifi():
    wifi_output_text.delete('1.0', tk.END)  # Clear previous output
    wifi_output_text.insert(tk.END, "Retrieving Wi-Fi network information...\n")
    # Get Wi-Fi network information using netsh command
    try:
        network_info = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode("utf-8")
        ssid_match = re.search(r"SSID\s+:\s+(.*)", network_info)
        if ssid_match:
            ssid = ssid_match.group(1).strip()
            wifi_output_text.insert(tk.END, f"Connected Wi-Fi Network: {ssid}\n")
        else:
            wifi_output_text.insert(tk.END, "Not connected to a Wi-Fi network\n")
    except subprocess.CalledProcessError:
        wifi_output_text.insert(tk.END, "Error retrieving Wi-Fi network information\n")

    # Get router location
    router_location = get_location("192.168.1.1")  # Assuming the router IP address is known

    # Get list of connected devices (ARP table)
    try:
        arp_output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        devices = re.findall(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]+)", arp_output)
        for ip_address, mac_address in devices:
            wifi_output_text.insert(tk.END, f"IP Address: {ip_address}, MAC Address: {mac_address}\n")
            wifi_output_text.insert(tk.END, "-"*50 + "\n")  # Add horizontal line after each IP address details
            # Check if IP address is multicast or broadcast
            if is_multicast_or_broadcast(ip_address):
                wifi_output_text.insert(tk.END, "Classification: Multicast/Broadcast\n")
                wifi_output_text.insert(tk.END, "Distance from router: N/A meters\n")
                wifi_output_text.insert(tk.END, "Location: Unknown\n")
            else:
                # Retrieve location information
                location_info = get_location(ip_address)
                distance = calculate_distance(ip_address)
                wifi_output_text.insert(tk.END, f"Location: {location_info}\n")
                wifi_output_text.insert(tk.END, f"Distance from router: {distance} meters\n")
                if location_info == router_location:
                    wifi_output_text.insert(tk.END, "Safe\n")
                else:
                    wifi_output_text.insert(tk.END, "Alert\n")
    except subprocess.CalledProcessError:
        wifi_output_text.insert(tk.END, "Error retrieving connected devices\n")

# Function to check if IP address is multicast or broadcast
def is_multicast_or_broadcast(ip_address):
    return ip_address.startswith("224.") or ip_address == "255.255.255.255"

# Function to retrieve location information based on IP address
def get_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data["status"] == "success":
            city = data["city"]
            country = data["country"]
            return f"{city}, {country}"
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error retrieving location information for IP {ip_address}: {e}")
        return "Unknown"

# Function to calculate distance based on signal strength (for illustration purposes only, actual distance calculation may vary)
def calculate_distance(ip_address):
    try:
        signal_output = subprocess.check_output(["ping", "-n", "1", ip_address]).decode("utf-8")
        match = re.search(r"Average = (\d+)ms", signal_output)
        if match:
            ping_time = int(match.group(1))
            # Example calculation for demonstration purposes only, adjust as needed
            # Assuming a linear relationship between ping time and distance
            return round(ping_time / 10)  # Adjust as needed based on your network conditions
        else:
            return "N/A"
    except subprocess.CalledProcessError:
        return "N/A"

# Create button to display performance details
performance_button = ttk.Button(root, text="PERFORMANCE", command=display_performance)
performance_button.grid(row=1, column=0, padx=10, pady=5, sticky="nw")

# Create button to hide performance details
back_button = ttk.Button(root, text="Hide Performance", command=hide_performance, state=tk.DISABLED)
back_button.grid(row=2, column=0, padx=10, pady=5, sticky="w")

# Create button to scan available connections
scan_button = ttk.Button(root, text="Scan Connections", command=scan_connections)
scan_button.grid(row=3, column=0, padx=10, pady=5, sticky="w")

# Label for IP address entry
ip_label = ttk.Label(root, text="Enter IP address:")
ip_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

# Entry for IP address input
ip_entry = ttk.Entry(root)
ip_entry.grid(row=5, column=0, padx=10, pady=5, sticky="w")

# Button to get IP details
get_ip_details_button = ttk.Button(root, text="Get IP Details", command=get_ip_details)
get_ip_details_button.grid(row=6, column=0, padx=10, pady=5, sticky="w")

# Text widget to display IP details
ip_details_text = tk.Text(root, height=10, width=40)
ip_details_text.grid(row=7, column=0, padx=10, pady=5, sticky="w")

# Text widget to display network connection details
connections_text = tk.Text(root, height=10, width=80)
connections_text.grid(row=8, column=0, padx=10, pady=5, sticky="w")

# Label for threat details
threat_label = ttk.Label(root, text="Threat Details:")
threat_label.grid(row=9, column=0, padx=10, pady=5, sticky="w")

# Text widget to display threat details
threat_text = tk.Text(root, height=10, width=80)
threat_text.grid(row=10, column=0, padx=10, pady=5, sticky="w")

# Create button to scan Wi-Fi
wifi_scan_button = ttk.Button(root, text="Scan WiFi", command=scan_wifi)
wifi_scan_button.grid(row=0, column=1, padx=10, pady=10, sticky="nw")

# Text widget to display Wi-Fi scan output
wifi_output_text = tk.Text(root, height=20, width=60)
wifi_output_text.grid(row=1, column=1, rowspan=10, padx=10, pady=10, sticky="nw")

root.mainloop()
