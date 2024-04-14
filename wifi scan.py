import subprocess
import re
import requests

# Function to retrieve Wi-Fi network information and connected devices
def get_wifi_info():
    # Get Wi-Fi network information using netsh command
    try:
        network_info = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode("utf-8")
        ssid_match = re.search(r"SSID\s+:\s+(.*)", network_info)
        if ssid_match:
            ssid = ssid_match.group(1).strip()
            print(f"Connected Wi-Fi Network: {ssid}")
        else:
            print("Not connected to a Wi-Fi network")
    except subprocess.CalledProcessError:
        print("Error retrieving Wi-Fi network information")

    # Get router location
    router_location = get_location("192.168.1.1")  # Assuming the router IP address is known

    # Get list of connected devices (ARP table)
    try:
        arp_output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        devices = re.findall(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F-]+)", arp_output)
        for ip_address, mac_address in devices:
            print(f"IP Address: {ip_address}, MAC Address: {mac_address}")
            # Check if IP address is multicast or broadcast
            if is_multicast_or_broadcast(ip_address):
                print("Classification: Multicast/Broadcast")
                print("Distance from router: N/A meters")
                print("Location: Unknown")
            else:
                # Retrieve location information
                location_info = get_location(ip_address)
                distance = calculate_distance(ip_address)
                print(f"Location: {location_info}")
                print(f"Distance from router: {distance} meters")
                if location_info == router_location:
                    print("Safe")
                else:
                    print("Alert")
    except subprocess.CalledProcessError:
        print("Error retrieving connected devices")

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

# Main function
def main():
    print("Retrieving Wi-Fi network information...")
    get_wifi_info()

if __name__ == "__main__":
    main()
