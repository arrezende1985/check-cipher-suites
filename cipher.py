# @Author: Alexandre Rezende
# @Date:   2023-05-23 11:27:30

import datetime
import base64
import binascii
import contextlib
import ipaddress
import os
import socket
import ssl
import warnings
from collections import defaultdict
from ipwhois import IPWhois


# ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'


def check_ciphersuite_protocol(host, port):
    # Create a custom SSL/TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Disable certificate verification
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Get all supported ciphersuites by the context
    ciphersuites = context.get_ciphers()

    # Group ciphersuites by TLS version
    ciphersuites_by_version = defaultdict(list)
    for ciphersuite in ciphersuites:
        tls_version = ciphersuite['protocol']
        ciphersuites_by_version[tls_version].append(ciphersuite)

    # Display ciphersuites by TLS version
    print(f"\n{Colors.BLUE}Compatible ciphersuites:{Colors.RESET}")
    for tls_version, ciphersuites in ciphersuites_by_version.items():
        print(f"{Colors.YELLOW}TLS protocol version: {tls_version}{Colors.RESET}")
        for ciphersuite in ciphersuites:
            print(f"  {Colors.GREEN}Algorithm:{Colors.RESET} {ciphersuite['name']}")
            if 'keySize' in ciphersuite:
                print(f"    {Colors.GREEN}Key size:{Colors.RESET} {ciphersuite['keySize']}")
        print()


def get_ip_addresses(host):
    # Get a list of IP addresses for the host
    ip_addresses = socket.gethostbyname_ex(host)[2]

    # Check if there are available IP addresses
    if len(ip_addresses) > 0:
        print(f"\n{Colors.YELLOW}IP Addresses:{Colors.RESET}")
        for ip in ip_addresses:
            print(f"  {Colors.YELLOW}IP Address:{Colors.RESET} {ip}")

            # Get domain information
            try:
                domain_info = socket.gethostbyaddr(ip)
                domain_name = domain_info[0]
                print(f"    {Colors.YELLOW}Domain:{Colors.RESET} {domain_name}")
                if len(domain_info[1]) > 0:
                    print(f"    {Colors.YELLOW}Hostname aliases:{Colors.RESET}")
                    for alias in domain_info[1]:
                        print(f"      {alias}")
                if len(domain_info[2]) > 0:
                    print(f"    {Colors.YELLOW}IP addresses associated with the domain:{Colors.RESET}")
                    for ip_alias in domain_info[2]:
                        print(f"      {ip_alias}")
            except socket.herror:
                print(f"    {Colors.YELLOW}Domain:{Colors.RESET} Not found")

            # Check the type of IP (Internet or Internal Network)
            obj = IPWhois(ip)
            info = obj.lookup_rdap()
            if info['asn_country_code']:
                print(f"    {Colors.YELLOW}IP Type:{Colors.RESET} Internet")
                print(f"    {Colors.YELLOW}Location:{Colors.RESET} {info['asn_country_code']} - {info['asn_description']}")
                print(f"    {Colors.YELLOW}ASN:{Colors.RESET} {info['asn']}")
                print(f"    {Colors.YELLOW}CIDR:{Colors.RESET} {info['network']['cidr']}")
            else:
                print(f"    {Colors.YELLOW}IP Type:{Colors.RESET} Internal Network")
            print()
    else:
        print(f"{Colors.YELLOW}No IP addresses found for the host {host}{Colors.RESET}")


# Clear the terminal
def clear_terminal():
    if os.name == 'posix':  # Unix-like system
        os.system('clear')
    elif os.name == 'nt':  # Windows system
        os.system('cls')


def main():
    clear_terminal()
    host = input("Enter the host: ")
    port = int(input("Enter the port: "))

    clear_terminal()
    print("Consulting information. Please wait...")

    clear_terminal()
    get_ip_addresses(host)
    check_ciphersuite_protocol(host, port)

    # Limpar variáveis
    host = None
    port = None


if __name__ == '__main__':
    main()
