import requests

def get_location(ip_address):
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
    return location, country, city, region, isp, postal, dns

ip_address = input("Enter the IP address: ")  # Take user input for the IP address
location, country, city, region, isp, postal, dns = get_location(ip_address)
if location:
    latitude, longitude = location.split(',')
    print(f"Latitude: {latitude}, Longitude: {longitude}")
    if country:
        print(f"Country: {country}")
    else:
        print("Country not found")
    if city:
        print(f"City: {city}")
    else:
        print("City not found")
    if region:
        print(f"Region: {region}")
    else:
        print("Region not found")
    if isp:
        print(f"ISP: {isp}")
    else:
        print("ISP not found")
    if postal:
        print(f"Postal Code: {postal}")
    else:
        print("Postal Code not found")
    if dns:
        print(f"Reverse DNS: {dns}")
    else:
        print("Reverse DNS not found")
else:
    print("Location not found")
