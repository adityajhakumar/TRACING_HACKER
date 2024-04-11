import psutil
from prettytable import PrettyTable

# Get all network connections
connections = psutil.net_connections(kind='inet')

# Define dictionaries for type and family meanings
type_meanings = {1: "TCP", 2: "UDP"}
family_meanings = {2: "AF_INET (IPv4)", 23: "AF_INET6 (IPv6)"}

# Create a PrettyTable instance
table = PrettyTable()
table.field_names = ["Type", "Family", "Local Address", "Local Port", "Remote Address", "Remote Port", "PID", "Process", "Status"]

# Add connections to the table
for conn in connections:
    type_meaning = type_meanings.get(conn.type, "Unknown Type")
    family_meaning = family_meanings.get(conn.family, "Unknown Family")
    
    local_addr, local_port = conn.laddr
    remote_addr, remote_port = conn.raddr if conn.raddr else ("", "")
    
    # Get process associated with the connection
    process = psutil.Process(conn.pid) if conn.pid else None
    process_name = process.name() if process else "N/A"
    
    # Get connection status
    status = "ESTABLISHED" if conn.status == psutil.CONN_ESTABLISHED else "LISTENING" if conn.status == psutil.CONN_LISTEN else "UNKNOWN"
    
    table.add_row([type_meaning, family_meaning, f"{local_addr}", f"{local_port}", f"{remote_addr}", f"{remote_port}", conn.pid or "N/A", process_name, status])

# Set column alignment
table.align = "l"

# Set column width
table.max_width = 30

# Set borders and header
table.horizontal_char = '-'
table.vertical_char = '|'
table.junction_char = '+'

# Print the table
print("Active Network Connections:")
print(table)


