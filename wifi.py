import subprocess
import socket

def resolve_device_name(ip_address):
    try:
        device_name, _, _ = socket.gethostbyaddr(ip_address)
        return device_name
    except socket.herror:
        return None

def get_connected_devices():
    try:
        # Run arp command to get details of connected devices
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
        output = result.stdout

        # Extract IP addresses and MAC addresses from the output
        devices = []
        for line in output.split('\n'):
            if "dynamic" in line.lower():
                parts = line.split()
                ip_address = parts[0]
                mac_address = parts[1]
                device_name = resolve_device_name(ip_address)
                manufacturer = None  # Placeholder for manufacturer information
                device = {'IP Address': ip_address, 'MAC Address': mac_address, 'Name': device_name, 'Manufacturer': manufacturer}
                devices.append(device)

        return devices
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        return None

if __name__ == "__main__":
    devices = get_connected_devices()
    if devices:
        print("Devices connected to the same WiFi network:")
        for device in devices:
            print(device)
    else:
        print("Failed to retrieve connected devices.")
