# DHCP Sniffer: Quick way to identify who's on your network passively (no one knows you're looking). 
# Great for a simple network inventory.

# This program detects the following:
# MAC address
# Hostname
# Requested IP address


from scapy.all import *
import time

def listen_dhcp():
    # Make sure it is DHCP with the filter options
    sniff(prn=print_packet, filter = 'udp and (port 67 or port 68)')

def print_packet(packet):
    
    # Initialise these variables to None at first
    target_mac, requested_ip, hostname, vendor_id = [None] *4

    # Get Mac address of the requestor:
    if packet.haslayer(Ether):
        target_mac = packet.getlayer(Ether).src

    # Get the DHCP options
    if packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options
        for item in dhcp_options:
            try:
                label, value = item
            except ValueError:
                continue
            if label == 'requested_addr':
                #get the reqeuested IP
                requested_ip = value
            elif label == 'hostname':
                #get the hostname of the device
                hostname = value.decode()
            elif label == 'vendor_class_id':
                #get the vendor ID
                vendor_id = value.decode()
                
    if target_mac and vendor_id and hostname and requested_ip:
        # if all variables are not None, pring the device details
        time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
        print(f'{time_now}: {target_mac} - {hostname} / {vendor_id} requested {requested_ip}')

if __name__ == '__main__':
    listen_dhcp()