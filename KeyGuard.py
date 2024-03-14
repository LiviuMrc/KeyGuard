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





def authenticate(iterations=10000, key_length=32):

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
        print("\nAuthenticated")
        
        while True:
            print("\nMeniu:")
            print("1. Add Entry")
            print("2. Search")
            print("3. Show All")
            print("4. Delete")

            print("5. Exit")

            optiune = input("Selectati optiunea: ")

            if optiune == "1":
                add_entry(file_path)
            elif optiune == "2":
                search_entry(file_path)
            elif optiune == "3":
                show_all_services(file_path)
            elif optiune == "4":
                delete_entry(file_path)
        
            






            elif optiune == "5":
                print("La revedere!")
                return
            else:
                print("Optiune invalida. Va rugam selectati din nou.")

            
                break

    else:
        print("Fail")

def add_entry(file_path):
    service = input("Service : ")
    uname = input("Username : ")
    passwd = input("Password : ")

    entry = f"\n{service}:{uname}:{passwd}"

    with open(file_path, "a") as file:
        file.write(entry)

    print("Entry added successfully.")

def search_entry(file_path):
    service_to_search = input("Enter the service name to search for: ")
    found = False

    with open(file_path, "r") as file:
        for line in file:
            if line.startswith(service_to_search + ":"):
                _, uname, passwd = line.strip().split(":")
                print(f"Service: {service_to_search}\nUsername: {uname}\nPassword: {passwd}")
                found = True
                break

    if not found:
        print("No entry found for the specified service.")

def show_all_services(file_path):
    print("List of all services and their credentials:")
    with open(file_path, "r") as file:
        # Skip the first two lines (salt and hash)
        next(file)
        next(file)
        for line in file:
            line = line.strip()
            if line and len(line.split(":")) == 3:
                service, uname, passwd = line.split(":")
                print(f"\nService: {service}\nUsername: {uname}\nPassword: {passwd}")

def delete_entry(file_path):
    service_to_delete = input("Enter the service name to delete: ")
    found = False
    updated_lines = []

    with open(file_path, "r") as file:
        # Read the first two lines (salt and hash) and add them to the updated lines
        updated_lines.append(file.readline())
        updated_lines.append(file.readline())

        # Check each subsequent line for the service to delete
        for line in file:
            if not line.startswith(service_to_delete + ":"):
                updated_lines.append(line)
            else:
                found = True

    if found:
        # Rewrite the file with the updated lines, removing any trailing newlines
        with open(file_path, "w") as file:
            for line in updated_lines:
                file.write(line.rstrip() + "\n")
        print("Entry for service '{}' deleted successfully.".format(service_to_delete))
    else:
        print("No entry found for the specified service.")







    




    

            




    
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
            authenticate()
        
            






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
