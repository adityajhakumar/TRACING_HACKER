import psutil
import socket
import datetime  # Import datetime module to handle date and time

# Get all network connections
connections = psutil.net_connections(kind='inet')

# Define dictionaries for type and family meanings
type_meanings = {1: "TCP", 2: "UDP"}
family_meanings = {2: "AF_INET (IPv4)", 23: "AF_INET6 (IPv6)"}

# Function to capture and print packets related to a connection
def capture_packets(local_addr, local_port, remote_addr, remote_port):
    print("Packet Summary:")
    try:
        # Create a raw socket and bind it to the local address and port
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer_socket.bind((local_addr, local_port))
        
        # Set socket options to include IP headers
        sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Enable promiscuous mode to capture all packets
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        # Capture packets for a short duration
        for _ in range(10):
            print(sniffer_socket.recvfrom(65565)[0])
    except Exception as e:
        print(f"Error occurred while capturing packets: {e}")
    finally:
        # Disable promiscuous mode and close the socket
        if 'sniffer_socket' in locals():
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer_socket.close()

# Function to print connection details
def print_connection_details(conn, index):
    type_meaning = type_meanings.get(conn.type, "Unknown Type")
    family_meaning = family_meanings.get(conn.family, "Unknown Family")
    
    local_addr, local_port = conn.laddr
    remote_addr, remote_port = conn.raddr if conn.raddr else ("", "")
    
    # Get process associated with the connection
    process = psutil.Process(conn.pid) if conn.pid else None
    process_name = process.name() if process else "N/A"
    
    # Get connection status
    status = "ESTABLISHED" if conn.status == psutil.CONN_ESTABLISHED else "LISTENING" if conn.status == psutil.CONN_LISTEN else "UNKNOWN"
    
    print(f"#{index} - Type: {type_meaning}")
    print(f"    Family: {family_meaning}")
    print(f"    Local Address: {local_addr}")
    print(f"    Local Port: {local_port}")
    print(f"    Remote Address: {remote_addr}")
    print(f"    Remote Port: {remote_port}")
    print(f"    PID: {conn.pid or 'N/A'}")
    print(f"    Process: {process_name}")
    print(f"    Status: {status}")
    
    # Get process creation time
    if process:
        create_time = datetime.datetime.fromtimestamp(process.create_time())
        print(f"    Process Creation Time: {create_time}")
    
    return process

# Print connection details and packet summaries
index = 1
processes = []
for conn in connections:
    if conn.status == psutil.CONN_ESTABLISHED:
        process = print_connection_details(conn, index)
        if process:
            processes.append(process)
        index += 1

# Prompt the user to select a connection or close a program
if index > 1:
    while True:
        try:
            selection = int(input("Enter the number of the connection to view the path or close its program (or 0 to exit): "))
            if selection == 0:
                break
            elif 1 <= selection < index:
                # Get the selected connection
                selected_conn = [conn for conn in connections if conn.status == psutil.CONN_ESTABLISHED][selection - 1]
                
                # Get the process associated with the selected connection
                selected_process = processes[selection - 1]
                
                # Print the path of the associated process
                print(f"Path of the associated process: {selected_process.exe()}")
                # Print the creation time of the associated process
                create_time = datetime.datetime.fromtimestamp(selected_process.create_time())
                print(f"Creation time of the associated process: {create_time}")
                
                # Ask user if they want to close the program
                close_program = input("Do you want to close this program? (yes/no): ").lower()
                if close_program == "yes":
                    selected_process.terminate()
                    print("Program terminated.")
                else:
                    print("Program not terminated.")
                
                break
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
else:
    print("No established connections found.")
