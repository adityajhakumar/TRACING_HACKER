import psutil
import time

# Constants for anomaly detection
CPU_THRESHOLD = 80  # CPU usage threshold (percentage)
MEMORY_THRESHOLD = 80  # Memory usage threshold (percentage)
DISK_THRESHOLD = 80  # Disk usage threshold (percentage)
NETWORK_THRESHOLD = 1024 * 1024 * 10  # Network threshold (bytes) - 10 MB/s

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

# Function to print details of all metrics
def print_metric_details(cpu_percent, memory_percent, disk_percent, network_bytes):
    print(f"CPU Usage: {cpu_percent}%")
    print(f"Memory Usage: {memory_percent}%")
    print(f"Disk Usage: {disk_percent}%")
    print(f"Network Usage: {convert_bytes_to_readable(network_bytes)}")

# Function to detect anomalies in system behavior
def detect_anomalies():
    cpu_percent = check_cpu_usage()
    memory_percent = check_memory_usage()
    disk_percent = check_disk_usage()
    network_bytes = check_network_usage()

    print_metric_details(cpu_percent, memory_percent, disk_percent, network_bytes)

def main():
    while True:
        detect_anomalies()
        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    main()
