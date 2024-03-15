import hashlib
from hashlib import pbkdf2_hmac
import os
import getpass
import binascii
import json



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

    auth_data = {
        "salt": salt.hex(),
        "hash": derived_key.hex()
    }

    username_pc = getpass.getuser()
    desktop_path = os.path.join("/Users", username_pc, "Desktop", "KeyGuard Test")
    auth_file_path = os.path.join(desktop_path, f"{username}_auth.json")
    data_file_path = os.path.join(desktop_path, f"{username}_data.json")

    os.makedirs(desktop_path, exist_ok=True)
    with open(auth_file_path, "w") as file:
        json.dump(auth_data, file, indent=4)

    with open(data_file_path, "w") as file:
        file.write("")  # Create an empty file

    print("Vault Created.")






def authenticate():
    name = input("What is your username?\n")
    masterpass = input("Masterpass:\n")
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
            print("\nAuthenticated")
            while True:
                print("\nMenu:")
                print("1. Add Entry")
                print("2. Search")
                print("3. Show All")
                print("4. Delete")
                print("5. Exit")

                option = input("Select an option: ")

                if option == "1":
                    add_entry(data_file_path)
                elif option == "2":
                    search_entry(data_file_path)
                elif option == "3":
                    show_all_services(data_file_path)
                elif option == "4":
                    delete_entry(data_file_path)
                elif option == "5":
                    print("Goodbye!")
                    return
                else:
                    print("Invalid option. Please try again.")
        else:
            print("Authentication failed.")
    else:
        print("This user's Vault does not exist, please try again.")


def add_entry(data_file_path):
    service = input("Service: ")
    uname = input("Username: ")
    passwd = input("Password: ")

    new_entry = {service: {"username": uname, "password": passwd}}

    with open(data_file_path, "r+") as file:
        content = file.read().strip()
        if content:
            data = json.loads(content)
        else:
            data = {}  # Initialize with an empty dictionary if the file is empty
        data.update(new_entry)
        file.seek(0)
        file.truncate()  # Truncate the file before writing the updated data
        json.dump(data, file, indent=4)

    print("Entry added successfully.")


def search_entry(data_file_path):
    service_to_search = input("Enter the service name to search for: ")
    with open(data_file_path) as file:
        data = json.load(file)
        if service_to_search in data:
            entry = data[service_to_search]
            print(f"Service: {service_to_search}\nUsername: {entry['username']}\nPassword: {entry['password']}")
        else:
            print("No entry found for the specified service.")

def show_all_services(data_file_path):
    print("List of all services and their credentials:")
    with open(data_file_path, "r") as file:
        content = file.read().strip()
        if content:
            data = json.loads(content)
            for service, entry in data.items():
                print(f"\nService: {service}\nUsername: {entry['username']}\nPassword: {entry['password']}")
        else:
            print("No entries gasite.")

def delete_entry(data_file_path):
    service_to_delete = input("Enter the service name to delete: ")
    with open(data_file_path, "r+") as file:
        data = json.load(file)
        if service_to_delete in data:
            del data[service_to_delete]
            file.seek(0)
            file.truncate()
            json.dump(data, file, indent=4)
            print(f"Entry for service '{service_to_delete}' deleted successfully.")
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
