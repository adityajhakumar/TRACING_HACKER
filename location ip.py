import requests

def get_location(ip_address):
    url = f"http://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    location = data.get("loc", None)
    country = data.get("country", None)
    return location, country

ip_address = input("Enter the IP address: ")  # Take user input for the IP address
location, country = get_location(ip_address)
if location:
    latitude, longitude = location.split(',')
    print(f"Latitude: {latitude}, Longitude: {longitude}")
    if country:
        print(f"Country: {country}")
    else:
        print("Country not found")
else:
    print("Location not found")
