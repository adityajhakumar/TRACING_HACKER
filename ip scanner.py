import ipinfo

# Initialize IPinfo client with your API token
access_token = 'YOUR_IPINFO_ACCESS_TOKEN'
handler = ipinfo.getHandler(access_token)

def is_proxy(ip):
    details = handler.getDetails(ip)
    if 'proxy' in details.all:
        return True
    return False

ip_address = input("Enter the IP address you want to check: ")

if is_proxy(ip_address):
    print(f"{ip_address} is likely a proxy.")
else:
    print(f"{ip_address} is not a proxy.")
