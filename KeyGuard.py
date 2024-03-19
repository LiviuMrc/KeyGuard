import pyotp
from hashlib import pbkdf2_hmac
import os
import getpass
import binascii
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import qrcode


def create_vault_key():
    username = input("Enter username:\n")
    masterpass = input("Enter the masterpassword:\n")

    masterpass_bin = masterpass.encode()
    username_bin = username.encode()

    salt = os.urandom(16)
    iterations = 10000
    key_length = 32
    key = username_bin + masterpass_bin

    derived_key = pbkdf2_hmac('sha256', key, salt, iterations, dklen=key_length)

    totp_secret = pyotp.random_base32()

    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="KeyGuard")

    # Generate the QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Display the QR code to the user
    img.show()

    totp = pyotp.TOTP(totp_secret)
    user_totp_token = input("Enter the TOTP token to confirm: ")
    if totp.verify(user_totp_token):
        print("TOTP confirmation successful!")

        img.close()
        # Encrypt the TOTP secret key
        cipher = AES.new(derived_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_totp_secret = cipher.encrypt(pad(totp_secret.encode(), AES.block_size))

        # Store the encrypted TOTP secret and other authentication data
        auth_data = {
            "salt": salt.hex(),
            "hash": derived_key.hex(),
            "totp": {
                "iv": iv.hex(),
                "data": binascii.hexlify(encrypted_totp_secret).decode()
            }
        }

        username_pc = getpass.getuser()
        desktop_path = os.path.join("/Users", username_pc, "Desktop", "KeyGuard Test")
        auth_file_path = os.path.join(desktop_path, f"{username}_auth.json")
        data_file_path = os.path.join(desktop_path, f"{username}_data.json")

        with open(data_file_path, "w") as file:
            file.write("")  # Create an empty file

        os.makedirs(desktop_path, exist_ok=True)
        with open(auth_file_path, "w") as file:
            json.dump(auth_data, file, indent=4)

        print("Vault Created.")
        del username, masterpass, masterpass_bin, username_bin,key,iterations,salt,key_length,derived_key,auth_data,username_pc,desktop_path,auth_file_path,file,img
    else:
            print("Invalid TOTP token. Please try again.")
            del username, masterpass, masterpass_bin, username_bin,key,iterations,salt,key_length,derived_key,username_pc,desktop_path,auth_file_path,file,img

def authenticate():
    name = input("What is your username?\n")
    masterpass = getpass.getpass("Master password:\n")
    masterpass = masterpass.encode()
    user = name.encode()

    username_pc = getpass.getuser()
    desktop_path = os.path.join("/Users", username_pc, "Desktop", "KeyGuard Test")
    auth_file_path = os.path.join(desktop_path, f"{name}_auth.json")
    data_file_path = os.path.join(desktop_path, f"{name}_data.json")

    if os.path.exists(auth_file_path):
        with open(auth_file_path) as file:
            auth_data = json.load(file)
            stored_salt = bytes.fromhex(auth_data["salt"])
            stored_hash = bytes.fromhex(auth_data["hash"])

        key = user + masterpass
        input_hash = pbkdf2_hmac('sha256', key, stored_salt, 10000, dklen=32)

        if input_hash == stored_hash:
            print("\nTOTP Verification:")

            # Decrypt and verify the TOTP token
            totp_data = auth_data["totp"]
            iv = bytes.fromhex(totp_data["iv"])
            encrypted_totp_secret = binascii.unhexlify(totp_data["data"])
            cipher = AES.new(input_hash, AES.MODE_CBC, iv=iv)
            decrypted_totp_secret = unpad(cipher.decrypt(encrypted_totp_secret), AES.block_size).decode()

            totp = pyotp.TOTP(decrypted_totp_secret)
            user_totp_token = input("Enter the TOTP token: ")
            if totp.verify(user_totp_token):
                print("TOTP verification successful!")
                
                # Proceed with the rest of your authentication process...
                while True:
                    print("\nMenu:")
                    print("1. Add Entry")
                    print("2. Search")
                    print("3. Show All")
                    print("4. Delete")
                    print("5. Exit")

                    option = input("Select an option: ")

                    if option == "1":
                        add_entry(data_file_path, input_hash)
                    elif option == "2":
                        search_entry(data_file_path, input_hash)
                    elif option == "3":
                        show_all_services(data_file_path, input_hash)
                    elif option == "4":
                        delete_entry(data_file_path)
                    elif option == "5":
                        print("Goodbye!")
                        return
                    else:
                        print("Invalid option. Please try again.")
            else:
                print("Invalid TOTP token.")
                return False
        else:
            print("Authentication failed.")
            return False
    else:
        print("This user's Vault does not exist, please try again.")
        return False
    
def add_entry(data_file_path, key):
    service = input("Service: ")
    uname = input("Username: ")
    passwd = input("Password: ")

    salt = os.urandom(16)
    derived_key = pbkdf2_hmac('sha256', key, salt, 10000, dklen=32)
    cipher = AES.new(derived_key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(f"{uname}:{passwd}".encode(), AES.block_size))

    new_entry = {
        service: {
            "salt": salt.hex(),
            "iv": iv.hex(),
            "data": binascii.hexlify(encrypted_data).decode()
        }
    }

    with open(data_file_path, "r+") as file:
        content = file.read().strip()
        if content:
            data = json.loads(content)
        else:
            data = {}
        data.update(new_entry)
        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

    print("Entry added successfully.")
    del key,service,uname,passwd,salt,derived_key,cipher,iv,encrypted_data,new_entry,data_file_path,data

def search_entry(data_file_path, key):
    service_to_search = input("Enter the service name to search for: ")
    with open(data_file_path) as file:
        content = file.read().strip()
        if not content:
            print("No entries found.")
            return
        data = json.loads(content)
        if service_to_search in data:
            entry = data[service_to_search]
            salt = bytes.fromhex(entry["salt"])
            iv = bytes.fromhex(entry["iv"])
            encrypted_data = binascii.unhexlify(entry["data"])

            derived_key = pbkdf2_hmac('sha256', key, salt, 10000, dklen=32)
            cipher = AES.new(derived_key, AES.MODE_CBC, iv=iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
            uname, passwd = decrypted_data.split(":")

            print(f"Service: {service_to_search}\nUsername: {uname}\nPassword: {passwd}")
            del derived_key,decrypted_data,uname,passwd,service_to_search
        else:
            print("No entry found for the specified service.")
            del derived_key,decrypted_data,uname,passwd,service_to_search
            

def show_all_services(data_file_path, key):
    print("List of all services and their credentials:")
    with open(data_file_path, "r") as file:
        content = file.read().strip()
        if content:
            data = json.loads(content)
            for service, entry in data.items():
                salt = bytes.fromhex(entry["salt"])
                iv = bytes.fromhex(entry["iv"])
                encrypted_data = binascii.unhexlify(entry["data"])

                derived_key = pbkdf2_hmac('sha256', key, salt, 10000, dklen=32)
                cipher = AES.new(derived_key, AES.MODE_CBC, iv=iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
                uname, passwd = decrypted_data.split(":")

                print(f"\nService: {service}\nUsername: {uname}\nPassword: {passwd}")
                del service,uname,passwd,decrypted_data,derived_key
        else:
            print("No entries found.")

def delete_entry(data_file_path):
    service_to_delete = input("Enter the service name to delete: ")
    with open(data_file_path, "r+") as file:
        content = file.read().strip()
        if not content:
            print("No entries found.")
            return
        data = json.loads(content)
        if service_to_delete in data:
            del data[service_to_delete]
            file.seek(0)
            file.truncate()
            json.dump(data, file, indent=4)
            print(f"Entry for service '{service_to_delete}' deleted successfully.")
            del service_to_delete
        else:
            print("No entry found for the specified service.")
            del service_to_delete

def main():
    while True:
        print("\nMenu:")
        print("1. Create Vault")
        print("2. Enter Vault")
        print("3. Exit")

        option = input("Select an option: ")

        if option == "1":
            create_vault_key()
        elif option == "2":
            authenticate()
        elif option == "3":
            print("Goodbye!")
            return
        else:
            print("Invalid option. Please try again.")

        continue_option = input("\nEnter 1 to go back to the main menu\n")
        if continue_option != "1":
            break

if __name__ == "__main__":
    main()
