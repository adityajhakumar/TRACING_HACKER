import psutil
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.animation as animation

# Function to update the plot with new data
def update_plot(frame, process_data, ax):
    # Get CPU usage percentage for each running process
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'connections']):
        if proc.info['cpu_percent'] > 20:  # Adjust the CPU usage threshold as needed
            process_name = proc.info['name']
            cpu_percent = proc.info['cpu_percent']
            connections = proc.info['connections']
            
            # Check if the process has network connections
            if connections:
                # Iterate over each network connection
                for conn in connections:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        # Check if the process has an associated window
                        try:
                            proc.exe()
                        except psutil.AccessDenied:
                            # Ignore AccessDenied exception for system processes
                            continue
                        except psutil.NoSuchProcess:
                            # Ignore NoSuchProcess exception if the process has terminated
                            continue
                        except psutil.ZombieProcess:
                            # Ignore ZombieProcess exception for zombie processes
                            continue
                        else:
                            # Print process details if CPU usage is high and no associated window is found
                            print(f"Process Name: {process_name}, CPU Usage: {cpu_percent}%")
                            print(f"    - Connection: {conn.laddr.ip}:{conn.laddr.port}")

    # Get CPU usage percentage for all processes
    cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
    
    # Append the new CPU usage to the data list
    process_data.append(np.mean(cpu_percent))
    
    # Limit the data list to a fixed length (e.g., keep only the last 50 data points)
    if len(process_data) > 50:
        process_data.pop(0)
    
    # Clear the previous plot and plot the updated data
    ax.clear()
    ax.plot(process_data, label='CPU Usage')
    ax.set_title('CPU Usage (%)')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('CPU Usage (%)')
    ax.legend(loc='upper left')

# Create an empty list to store CPU usage data
process_data = []

# Create a figure and axis for the plot
fig, ax = plt.subplots()

# Use FuncAnimation to update the plot every second
ani = animation.FuncAnimation(fig, update_plot, fargs=(process_data, ax), interval=1000, save_count=10)

# Show the dynamic plot
plt.show()
