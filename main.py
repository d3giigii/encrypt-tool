import os

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def display_menu():
    """Display the menu to user in the CLI."""
    
    display_menu.options = [
        "Create a file.",
        "Encrypt a file.",
        "Decrypt a file.",
        "Cleanup files.",
        "Exit."
    ]
    
    print()
    for i, txt in enumerate(display_menu.options):
        print(f"{i+1}: {txt}")

def is_valid_input():
    """Return True if input is valid for program schema."""
    # Schema validation. 

    # Logic validation. 

def sanitize_input(txt: str):
    """Return a copy of the string with suspect characters removed."""
    INVALID_CHARS = [';', '|', '&', "\"", "\'"]
    return "".join([i for i in str(txt) if not i in INVALID_CHARS])

def get_input(txt):
    """Return a copy of input from the user after it is sanitized."""
    raw = int
    try:
        # Get input from user. 
        raw = input(f"{txt}").strip()
        raw = sanitize_input(raw)
    except Exception:
        print("Error: Invalid input. Try again.")

    # TODO: Linter is making raw red. Should be yellow if anything. 
    return raw

def get_menu_input() -> int:
    """Retrieve choice from user in the CLI.

    Raises:
        Exception: User input is not exactly a single integer. 

    Returns:
        int: Sanitized user input. 
    """

    """
    Thoughts: While raised exceptions should be as narrow as possible, for the 
    purposes of maximizing security and reliability (which I am trying to 
    showcase), a broad catch-all exception works well. 
    """

    raw = None
    try:
        # Get input from user. 
        raw = int(input("Select option: ").strip())
        raw = int(sanitize_input(raw))

        # Schema validation. Input should be a single integer. 
        if not isinstance(raw, int) or len(str(raw)) != 1:
            raise Exception
        
        # Logic validation. Input should be between 1 and the number of options.
        if not 0 <= raw <= len(display_menu.options):
            raise Exception
    
    except Exception:
        print("Error: Invalid input. Try again.")

    # TODO: Linter is making raw red. Should be yellow if anything. 
    return raw

def create_file():
    print("Create file selected.")

    # Get file name and message from user. 
    file_name = get_input("Enter file name: ")
    message = get_input("Enter message: ")
    if not ".txt" in file_name:
        file_name += ".txt"

    # Create file with cleartext message. 
    with open(f"{file_name}", "w+") as file:
        file.writelines(message)

def encrypt_file():
    print("Encrypt file selected.")

    file_name = get_input("Enter file name: ")
    file_data = None

    # Create file with cleartext message. 
    with open(f"{file_name}", "r") as file:
        file_data = file.read()

    # Encrypt contents of cleartext message. 
    data = file_data.encode()

    # Generate and save AES key. 
    aes_key = get_random_bytes(16)
    with open("aes.key", "wb") as file:
        file.write(aes_key)

    # Encrypt message. 
    cipher = AES.new(aes_key, AES.MODE_OCB)
    cipher_text, cipher_tag = cipher.encrypt_and_digest(data)
    assert len(cipher.nonce) == 15

    # Save encrypted message. 
    with open("message_encrypted.bin", "wb") as file:
        file.write(cipher_tag)
        file.write(cipher.nonce)
        file.write(cipher_text)

def decrypt_file():
    print("Decrypt file selected.")

    # Load the AES key. 
    try: 
        with open("aes.key", "rb") as key_file:
            aes_key = key_file.read()
    except FileNotFoundError:
        print("Error: No key file found. Regenerate message.")        
    except Exception as e:
        print(f"Error: {e}")

    # Load the encrypted file. 
    try:
        cipher_tag, cipher_nonce, cipher_text = None, None, None
        with open("message_encrypted.bin", "rb") as file:
            cipher_tag = file.read(16)
            cipher_nonce = file.read(15)
            cipher_text = file.read()
    except FileNotFoundError:
        print("Error: Message file not found. Regenerate message.")
    except Exception as e:
        print(f"Error: {e}")
    
    # Decrypt the file. 
    should_save_file = False
    cipher = AES.new(aes_key, AES.MODE_OCB, nonce=cipher_nonce)
    try:
        clear_text = cipher.decrypt_and_verify(cipher_text, cipher_tag)
        print(f"Message: {clear_text.decode()}")
        should_save_file = True
    except ValueError:
        print("Warning: The file was altered! Decrypted message not saved.")
     
    # Save decrypted message to file. 
    if should_save_file:
        try:
            with open("message_decrypted.txt", "wb") as file:
                file.write(clear_text)
        except Exception as e:
            print(f"Error: {e}")

def cleanup_files():
    
    files_to_remove = [
        "aes.key",
        "message.txt",
        "message_encrypted.bin",
        "message_decrypted.txt"
    ]

    for file in files_to_remove:        
        try: 
            os.remove(file)
        except FileNotFoundError as e:
            print(f"Warning: {e}")
        except Exception as e:
            print(f"Error: {e}")

def main():
    # Welcome user. 
    print("\nWelcome to Encryt-Tool!")    

    # Enter main program loop.
    while True:
        
        # Display menu to the user. 
        display_menu()

        # Get the menu choice from user. 
        user_input = get_menu_input()

        # Process the menu choice from user. 
        if user_input == 1:
            create_file()
        elif user_input == 2:
            encrypt_file()
        elif user_input == 3:
            decrypt_file()
        elif user_input == 4:
            cleanup_files()
        elif user_input == 5:
            break

    # Thank user. 
    print("\nThank you for using Encrypt-Tool!\n")

if __name__ == "__main__":
    main()
