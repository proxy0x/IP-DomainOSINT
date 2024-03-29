
# IP-Domain-OSINT

IP/Domain OSINT is a Python-based open-source intelligence (OSINT) tool designed for conducting investigations and gathering information about IP addresses and domains. It provides a user-friendly graphical interface and integrates various data sources to retrieve details such as geolocation, WHOIS information, SSL/TLS details, and more.

# Features

- IP Address Lookup: Retrieve detailed information about an IPv4 or IPv6 address, including geolocation, ISP details, and AS information.

- Domain Information: Obtain WHOIS data for a given domain, including registrar information, creation and expiration dates, and name server details.

- SSL/TLS Information: Fetch SSL/TLS details for a domain, such as protocol, cipher, issuer, and expiry date.

- Subdomain Enumeration: Optionally use Sublist3r to discover subdomains associated with a domain.

- Geographical Mapping: Visualize the geolocation of an IP address on an interactive map.

- Graphical User Interface (GUI): User-friendly interface with a sleek design for ease of use.

# Installation For Linux Users

- Click the Green Code Button and Download the Zip File (required for Sublist3r to work)

- Extract the Zip

- ```git clone --recursive https://github.com/proxy0x/IP-DomainOSINT.git```

- ```cd IP-DomainOSINT```

- ```python3 -m venv venv```

- ```source venv/bin/activate```

- ```sudo apt-get install python3-tk```

- ```pip install -r requirements.txt```

# Run the Tool

YOU MUST COPY THE PATH OF THE .py TO RUN. Exmaple below.

- ```python3 your/path/to/IPDomainOSINT.py```

If You Want to Deactivate the Virtual Environment:

- ```deactivate```

![Screenshot 2024-02-19 165031](https://github.com/proxy0x/IP-DomainOSINT/assets/140286530/86794df4-7dc8-459b-ab64-e8992ae7a3d7)

# Using Sublist3r

- ```cd IP-DomainOSINT/src/Sublist3r```

- ```python sublist3r.py -d example.com```

# Installation for Windows Users 

- Click the Green Code Button and Download the Zip File (required for Sublist3r to work)

- Extract the Zip

- ```git clone --recursive https://github.com/proxy0x/IP-DomainOSINT.git```

- ```cd IP-DomainOSINT```

- ```python3 -m venv venv```
  
- ```source venv/Scripts/activate``` (Git Bash)
- ```venv\Scripts\activate``` (cmd & Powershell)

- ```pip install -r requirements.txt```

# Run the Tool

YOU MUST COPY THE PATH OF THE .py TO RUN. Exmaple below.

- ```python your/path/to/IPDomainOSINT.py```

If You Want to Deactivate the Virtual Environment:

- ```deactivate```

![Screenshot 2024-02-19 165405](https://github.com/proxy0x/IP-DomainOSINT/assets/140286530/f2d55da1-6925-466d-be03-728e02a8727d)

# Using Sublist3r

- ```cd src/Sublist3r```

- ```python sublist3r.py -d example.com```

# Usage 
- Launch the application and enter the target IP address or domain.

- Click the "Search" button to initiate the investigation.

- View comprehensive results in the Treeview widget, including IP information, domain details, and SSL/TLS data.

# Dependencies Python 3.x

- Requests

- Tkinter

- Geopy

- Folium

- IPWhois

# Acknowledgments 
- IP/Domain OSINT utilizes Sublist3r for subdomain enumeration. For more information, refer to Sublist3r GitHub repository.

# License 
- This project is licensed under the MIT License - see the LICENSE file for details.
