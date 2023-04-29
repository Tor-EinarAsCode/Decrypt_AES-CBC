import csv
import requests
from ipwhois import IPWhois
import json
from operator import itemgetter

# Funksjon for å hente geolokasjonsdata
def get_geolocation(ip_address):
    url = f"https://ipgeolocation.abstractapi.com/v1/?api_key=4ed5f4f4b8c045869a26add96f54bb5b&ip_address={ip_address}"
    response = requests.get(url)
    return response.json()

# Funksjon for å hente Virustotal data
def get_virustotal_data(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    header = {"x-apikey": api_key}
    response = requests.get(url, headers=header)
    return response.json()

# Funksjon for å hente Whois data
def get_whois_data(ip_address):
    ipwhois = IPWhois(ip_address)
    whois = ipwhois.lookup_rdap()
    return whois

# Funksjon for å hente HTTP-feil per bruker
def get_http_errors_per_user(ip_address):
    url = f"https://YourLogSourceAPI/entries?ip_address={ip_address}"  # Juster denne URL-en i henhold til din faktiske API
    response = requests.get(url)
    return response.json()

# Listene for å lagre IP-adresser, data fra APIene og HTTP-feil per bruker
remote_ips = []
data = {}
http_errors_per_user = {}

# Åpne og les CSV-filen
with open("C:\data.csv", mode="r") as file:
    csvFile = csv.reader(file)
    headers = next(csvFile)

    remote_ip_data = headers.index("RemoteIP")

    # Legg til hver remote IP-adresse i listen remote_ips
    for row in csvFile:
        remoteIP = row[remote_ip_data]
        remote_ips.append(remoteIP)

# For hver remote IP-adresse i remote_ips
for remoteIP in remote_ips:
    # Hent geolokasjonsdata, Virustotal-data og Whois-data
    GL_data = get_geolocation(remoteIP)
    VT_data = get_virustotal_data(remoteIP, api_key="5082e79a7c4309bf7692ac9f59f25400e63eb1152e84f7bb513a1f97fd549535")
    whois_data = get_whois_data(remoteIP)

    # Legg dataene til i data-dictionaryen
    data[remoteIP] = {
        "Data fra Geolocation": GL_data,
        "Data fra Virustotal": VT_data,
        "Data fra Whois": whois_data,
    }

    # Hent HTTP-feil per bruker og legg dataene til i http_errors_per_user-dictionaryen
    http_errors = get_http_errors_per_user(remoteIP)
    for error in http_errors:
        user = error['username']  # Juster dette i henhold til din faktiske datastruktur
        if user not in http_errors_per_user:
            http_errors_per_user[user] = 0
        http_errors_per_user[user] += 1

# Sorter brukerne i http_errors_per_user etter antall feil i synkende rekkefølge og skriv ut resultatet
sorted_users = sorted(http_errors_per_user.items(), key=itemgetter(1), reverse=True)
for user, error_count in sorted_users:
    print(f'Bruker: {user}, Antall HTTP-feil: {error_count}')

# Lagrer filen som en .json fil
# indent er satt til en slik at dataen blir mer oversiktig
with open("case_data.json", "w") as json_file:
    json.dump(data, json_file, indent=1)

# om ønsket data skal i en fil eller bare printet ut så har jeg lagt til en print funksjon
json_data = json.dumps(data, indent=1)
print(json_data)
