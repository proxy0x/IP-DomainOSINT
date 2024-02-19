
# IP-Domain-OSINT

IP/Domain OSINT is a Python-based open-source intelligence (OSINT) tool designed for conducting investigations and gathering information about IP addresses and domains. It provides a user-friendly graphical interface and integrates various data sources to retrieve details such as geolocation, WHOIS information, SSL/TLS details, and more.

# Features
IP Address Lookup: Retrieve detailed information about an IPv4 or IPv6 address, including geolocation, ISP details, and AS information.

Domain Information: Obtain WHOIS data for a given domain, including registrar information, creation and expiration dates, and name server details.

SSL/TLS Information: Fetch SSL/TLS details for a domain, such as protocol, cipher, issuer, and expiry date.

Subdomain Enumeration: Optionally use Sublist3r to discover subdomains associated with a domain.

Geographical Mapping: Visualize the geolocation of an IP address on an interactive map.

Graphical User Interface (GUI): User-friendly interface with a sleek design for ease of use.

# Installation For Linux Users

git clone https://github.com/proxy0x/IP-Domain-OSINT.git

cd IP-Domain-OSINT

python3 -m venv venv

source venv/bin/activate

sudo apt-get install python3-tk

pip install -r requirements.txt

Run the Tool:

python3 IPDomainOSINT.py

Deactivate the Virtual Environment:

deactivate

# Installation for Windows Users 
git clone https://github.com/proxy0x/IP-Domain-OSINT.git

cd IP-Domain-OSINT

python3 -m venv venv

source venv/Scripts/activate

pip install -r requirements.txt

Run the Tool:

python3 IPDomainOSINT.py

If You Want to Deactivate the Virtual Environment:

deactivate

#Usage 
Launch the application and enter the target IP address or domain.

Optionally enable Sublist3r to enumerate subdomains.

Click the "Search" button to initiate the investigation.

View comprehensive results in the Treeview widget, including IP information, domain details, and SSL/TLS data.

# Dependencies Python 3.x

Requests

Tkinter

Geopy

Folium

IPWhois

# Acknowledgments 
IP/Domain OSINT utilizes Sublist3r for subdomain enumeration. For more information, refer to Sublist3r GitHub repository.

#License 

This project is licensed under the MIT License - see the LICENSE file for details.
