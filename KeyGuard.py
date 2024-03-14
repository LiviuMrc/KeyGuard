import hashlib
from hashlib import pbkdf2_hmac
import os
import getpass
import binascii


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
    print("Derived key:", derived_key.hex())

    username_pc = getpass.getuser()
    desktop_path = os.path.join("/Users", username_pc, "Desktop","KeyGuard Test")
    file_path = os.path.join(desktop_path, f"{username}'s Vault.txt")

    salt_hex = salt.hex()
    derived_key_hex = derived_key.hex()

    os.makedirs(desktop_path, exist_ok=True)
    with open(file_path, "w") as file:
        file.write(salt_hex)
        file.write("\n")
        file.write(derived_key_hex)

    print("Vault Created.")





def verify_password(iterations=10000, key_length=32):

    while True:

        name = input("What is your username ?\n")

        username_pc = getpass.getuser()
        desktop_path = os.path.join("/Users", username_pc, "Desktop","KeyGuard Test")
        file_path = os.path.join(desktop_path, f"{name}'s Vault.txt")

        if os.path.exists(file_path):
            with open(file_path) as file:
                stored_salt = file.readline().strip()
                stored_hash = file.readline().strip()
                stored_salt = bytes.fromhex(stored_salt)
                stored_hash = bytes.fromhex(stored_hash)

            break
        else:
            print("This user's Vault does not exist, please try again:\n")


        break

    masterpass = input("Masterpass:")
    masterpass = masterpass.encode()
    user = name.encode()

    key = user + masterpass

    input_hash = pbkdf2_hmac('sha256',key,stored_salt,iterations,dklen=key_length)

    if input_hash == stored_hash:
        print("Authenticated")
    else:
        print("Fail")




    

    
            




    

def main():
    while True:
        print("\nMeniu:")
        print("1. Creaza vault")
        print("2. Enter Vault")
        print("5. Exit")

        optiune = input("Selectati optiunea: ")

        if optiune == "1":
            create_vault_key()
        elif optiune == "2":
            verify_password()
        
            






        elif optiune == "5":
            print("La revedere!")
            return
        else:
            print("Optiune invalida. Va rugam selectati din nou.")

        continua = input("\nEnter 1 to go Back\n")
        if continua != "1":
            break


if __name__ == "__main__":
   main()
