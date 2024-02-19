import requests
import json
import re
import tkinter as tk
from tkinter import ttk, messagebox
from ttkthemes import ThemedTk, ThemedStyle
import socket
from geopy.geocoders import Nominatim
import folium
import webbrowser
import os
import ipwhois
import ssl
import sys
import subprocess

class IPDomainOSINT:
    def __init__(self, root):
        self.root = root
        self.root.title("IP/Domain OSINT")

        # Get the directory where the script is located
        script_directory = os.path.dirname(os.path.abspath(__file__))
        
        # Set the window size
        self.root.geometry("800x370")

        self.root.resizable(False, False)

        # ASCII art
        ascii_art = r"""
._____. ._____.
| ._. | | ._. |
| !_| |_|_|_! |
!___| |_______!
.___|_|_| |___.
| ._____| |_. |
| !_! | | !_! |
!_____! !_____!

        """
        self.ascii_label = tk.Label(self.root, text=ascii_art, font=("Courier", 8), foreground="#F0F0F0", background="#2E2E2E")

        self.create_widgets()

    def create_widgets(self):
        # Set background to black
        self.root.configure(bg="#2E2E2E")

        # IP Address Entry
        self.ip_label = ttk.Label(self.root, text="Enter IPv4 or IPv6 Address:", foreground="#E6DCDA", background="#2E2E2E")
        self.ip_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.ip_entry = ttk.Entry(self.root)
        self.ip_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        self.ip_label.place(x=10, y=50)
        self.ip_entry.place(x=390, y=50)

        # Domain Entry
        self.domain_label = ttk.Label(self.root, text="Enter Domain:", foreground="#E6DCDA", background="#2E2E2E")
        self.domain_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        self.domain_entry = ttk.Entry(self.root)
        self.domain_entry.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W)
        self.domain_label.place(x=10, y=20)
        self.domain_entry.place(x=390, y=20)

        # Place ASCII art at a specific location
        self.ascii_label.place(x=690, y=-18)

        # Search Button
        self.search_button = ttk.Button(self.root, text="Search", command=self.on_search, style="Green.TButton")
        self.search_button.grid(row=5, column=1, columnspan=2, pady=10)
        self.search_button.place(x=435, y=85)

        # Result Display
        self.result_label = ttk.Label(self.root, text="Results:", foreground="#E6DCDA", background="#2E2E2E")
        self.result_label.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)
        self.result_label.place(x=370, y=145)

        # Treeview
        self.tree = ttk.Treeview(self.root, columns=('Category', 'Value'), show='headings', style="Green.Treeview")
        self.tree.column('Category', width=200, anchor='center')  # Adjust width as needed
        self.tree.column('Value', anchor='center', stretch=True, width=1000)  # Adjust width as needed
        self.tree.heading('Category', text='Category')
        self.tree.heading('Value', text='Value')

        # Add a vertical scrollbar
        tree_scrollbar_y = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview, style="TScrollbar")
        self.tree.configure(yscrollcommand=tree_scrollbar_y.set)

        # Add a horizontal scrollbar
        tree_scrollbar_x = ttk.Scrollbar(self.root, orient="horizontal", command=self.tree.xview, style="TScrollbar")
        self.tree.configure(xscrollcommand=tree_scrollbar_x.set)

        # Place the Treeview in the grid
        self.tree.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky=tk.W)

        # Place the vertical scrollbar in the grid
        tree_scrollbar_y.grid(row=6, column=2, sticky="ns")

        # Place the horizontal scrollbar in the grid
        tree_scrollbar_x.grid(row=7, column=0, columnspan=2, sticky="ew")

        # Themed Style
        style = ThemedStyle(self.root)  # Use ThemedStyle

        # Apply the equilux theme to the entry boxes
        style.configure("TEntry", background=style.lookup("TFrame", "background"), fieldbackground=style.lookup("TFrame", "background"), foreground=style.lookup("TFrame", "foreground"))

        # Configure row and column weights for expansion
        self.root.grid_rowconfigure(5, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def get_ip_info(self, ip_address):
        try:
            # Original IP information
            url_ip = f"http://ip-api.com/json/{ip_address}"
            response_ip = requests.get(url_ip)
            data_ip = response_ip.json()

            # Geolocation information
            geolocator = Nominatim(user_agent="osint_tool")
            location_info = geolocator.reverse((data_ip.get('lat', 0), data_ip.get('lon', 0)), language='en')

            # AS information using ipwhois library
            as_info = self.get_as_info(ip_address)

            # Create a folium map centered on the IP address location
            map_center = [data_ip.get('lat', 0), data_ip.get('lon', 0)]
            my_map = folium.Map(location=map_center, zoom_start=13)

            # Add a marker for the IP address location
            folium.Marker(map_center, popup=f"IP Address: {ip_address}\nLocation: {location_info.address if location_info else 'N/A'}").add_to(my_map)

            # Save the map to an HTML file
            map_file_path = "ip_address_map.html"
            my_map.save(map_file_path)

            # Open the map file in a web browser
            webbrowser.open(os.path.abspath(map_file_path))

            # Return other information
            return {
                "IP Address": data_ip.get('query', 'N/A'),
                "City": data_ip.get('city', 'N/A'),
                "Region": data_ip.get('regionName', 'N/A'),
                "Country": data_ip.get('country', 'N/A'),
                "ISP": data_ip.get('isp', 'N/A'),
                "Organization": data_ip.get('org', 'N/A'),
                "Latitude": data_ip.get('lat', 'N/A'),
                "Longitude": data_ip.get('lon', 'N/A'),
                "Location (Geocoded)": location_info.address if location_info else "N/A",
                "Map": map_file_path,
                "AS Number": as_info['asn'],
                "AS Name": as_info['asn_description'],
            }

        except Exception as e:
            print(f"Error getting IP information: {e}")
            return {"Error": "Unable to retrieve IP information"}

    @classmethod
    def get_open_ports(cls, ip_address):
        # Retrieve information about open ports using socket
        open_ports = []
        try:
            for port in range(1, 1025):  # Check common ports
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except Exception as e:
            print(f"Error getting open ports: {e}")
        return open_ports

    def get_whois_info(self, domain):
        try:
            url = f"https://www.whois.com/whois/{domain}"
            response = requests.get(url)
            data = response.text

            # SSL/TLS information
            ssl_info = self.get_ssl_info(domain)

            # Ensure ip_address is defined before using it
            ip_address = self.ip_entry.get()

            # Extract relevant WHOIS information
            whois_info = {
                "Domain": domain,
                "Registrar": self.extract_value(data, "Registrar"),
                "Creation Date": self.extract_value(data, "Creation Date"),
                "Updated Date": self.extract_value(data, "Updated Date"),
                "Expiration Date": self.extract_value(data, "Expiration Date"),
                "Name Servers": self.extract_value(data, "Name Server").split(),
                "Registrant Organization": self.extract_value(data, "Registrant Organization"),
                "Registrant Country": self.extract_value(data, "Registrant Country"),
                "IPv4 Addresses": self.get_ip_addresses(domain),
                "IPv6 Addresses": self.get_ip_addresses(domain, ip_type="ipv6"),
                "SSL/TLS Info": ssl_info
            }

            return whois_info

        except Exception as e:
            print(f"Error getting WHOIS information: {e}")
            return {"Error": "Unable to retrieve WHOIS information"}

    def get_ssl_info(self, domain):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()

            # Extracting relevant SSL/TLS information
            ssl_info = {
                "SSL/TLS Protocol": cert.get("protocol", "N/A"),
                "SSL/TLS Cipher": cert.get("cipher", "N/A"),
                "SSL/TLS Issuer": cert.get("issuer", ((("organizationName", "N/A"),),))[0][0][1],
                "SSL/TLS Expiry Date": cert.get("notAfter", "N/A"),
            }

            return ssl_info
        except Exception as e:
            print(f"Error getting SSL/TLS information: {e}")
            return {"Error": "Unable to retrieve SSL/TLS information"}

    def get_as_info(self, ip_address):
        # Retrieve AS information using ipwhois library
        try:
            obj = ipwhois.IPWhois(ip_address)
            result = obj.lookup_rdap()
            return {
                "asn": result['asn'],
                "asn_description": result['asn_description']
            }
        except Exception as e:
            print(f"Error getting AS information: {e}")
            return {"asn": "N/A", "asn_description": "N/A"}

    def extract_value(self, data, key):
        start_index = data.find(key)
        end_index = data.find('\n', start_index)
        value = data[start_index:end_index].split(':')[-1].strip()
        return value

    def get_ip_addresses(self, domain, ip_type="ipv4"):
        try:
            ip_addresses = []

            # Get both IPv4 and IPv6 addresses
            for info in socket.getaddrinfo(domain, None):
                ip = info[4][0]
                if ip_type == "ipv4" and ":" not in ip:
                    ip_addresses.append(ip)
                elif ip_type == "ipv6" and ":" in ip:
                    ip_addresses.append(ip)

            return ", ".join(ip_addresses) if ip_addresses else "N/A"
        except (socket.gaierror, IndexError):
            return "N/A"

    def on_search(self):
        ip_address = self.ip_entry.get()
        domain = self.domain_entry.get()

        self.tree.delete(*self.tree.get_children())

        if not ip_address and not domain:
            messagebox.showwarning("Empty Input", "Please enter an IP address or domain.")
            return

        if ip_address and domain:
            messagebox.showwarning("Invalid Input", "Please enter either an IP address or a domain, not both.")
            return

        if self.is_valid_ip(ip_address):
            self.display_loading_animation()
            self.root.after(1000, lambda: self.display_result(self.get_ip_info(ip_address)))
        elif self.is_valid_domain(domain):
            self.display_loading_animation()
            self.root.after(1000, lambda: self.display_result(self.get_whois_info(domain)))

        else:
            messagebox.showwarning("Invalid Input", "Please enter a valid IP address or domain.")

    def display_loading_animation(self):
        loading_label = ttk.Label(self.root, text="Searching...", font=("Helvetica", 12, "bold"), foreground="#FFFFFF", background="#2E2E2E")
        loading_label.place(x=320, y=85)
        self.root.update()
        self.root.after(2000, lambda: loading_label.destroy())  # Adjust the time as needed

    def is_valid_ip(self, ip):
        # Use regex to check if the entered string is a valid IPv4 or IPv6 address
        ip_regex = re.compile(r'^(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\S+)$')
        return ip_regex.match(ip)

    def is_valid_domain(self, domain):
        # Use regex to check if the entered string is a valid domain
        domain_regex = re.compile(
            r'^(http://www\.|https://www\.|http://|https://)?'
            r'([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
            r'(\.[a-zA-Z]{2,})([/\w\.-]*)*/?$'
        )
        return domain_regex.match(domain)

    def display_result(self, result):
        for category, value in result.items():
            self.tree.insert("", "end", values=(category, value))


if __name__ == "__main__":
    root = tk.Tk()
    app = IPDomainOSINT(root)
    root.mainloop()







