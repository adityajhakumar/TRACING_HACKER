import pandas as pd

# Load the CSV file into a DataFrame
csv_file = r"C:\Users\adity\Downloads\List_of_TCP_and_UDP_port_numbers_2.csv"  # Replace with your file path
df = pd.read_csv(csv_file)

# Take input of the value from the first column
input_value = input("Enter the value from the first column (Port): ")

# Check if the input value exists in the first column
if input_value in df['Port'].values:
    # Get the corresponding values from other columns
    corresponding_values = df[df['Port'] == input_value].iloc[:, 1:]  # Assuming you want values from the second column onwards
    print("Corresponding values:")
    print(corresponding_values)
else:
    print("Input value not found in the first column.")
