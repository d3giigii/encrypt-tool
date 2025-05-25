"""
Encrypt-Tool CLI

This module provides a simple command-line interface for secure file encryption
and decryption using AES-128 in OCB mode. Users can create text files, encrypt
them with authenticated encryption, decrypt them with integrity verification,
and clean up working files.

All operations occur in a 'working/' directiory for isolated file handling.

This program should not be used in public or production environments. 

Author: Logan Hammond; lhammond997@gmail.com
"""

# TODO: Fix packaging and distribution.
# TODO: Implement additional forms of encryption with customizable options.

import os

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def display_menu() -> None:
    """Display the menu to user in the CLI.

    Returns:
        None
    """

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

def sanitize_input(txt: str) -> str:
    """Return a copy of the string with suspect characters removed.

    Args:
        txt (str): The input string to sanitize.

    Returns:
        str: A cleaned version of the input string.
    """

    invalid_chars = [';', '|', '&', "\"", "\'"]
    return "".join([i for i in str(txt) if not i in invalid_chars])

def get_input(txt: str) -> str:
    """Return a copy of input from the user after it is sanitized.

    Args:
        txt (str): Prompt to display to the user.

    Returns:
        str: Sanitized user input string.
    """

    raw = input(f"{txt}").strip()
    return sanitize_input(raw)

def get_menu_input() -> int:
    """Retrieve choice from user in the CLI menu.

    Raises:
        ValueError: User input does pass schema or logic validation after 
        sanitization.

    Returns:
        int: Sanitized user input.
    """

    try:
        raw = int(get_input("Select option: "))
        # Schema validation. Input should be a single integer.
        if not isinstance(raw, int) or len(str(raw)) != 1:
            raise ValueError
        # Logic validation. Input should be between 1 and the number of options.
        if not 0 <= raw <= len(display_menu.options):
            raise ValueError
        return raw
    except ValueError as e:
        print(f"Error: {e}")

    return int()

def create_file(file_name: str, file_msg: str) -> None:
    """Create a file with given name and message.

    Args:
        file_name (str): Name of the file to create.
        file_msg (str): Message content to write into the file.

    Returns:
        None
    """

    print("Create file selected.")

    # Ensure file name ends with .txt.
    if not (len(file_name) >= 4 and file_name[-4:] == ".txt"):
        file_name += ".txt"

    # Create file with cleartext message.
    with open(f"working/{file_name}", "w+", encoding="utf-8") as file:
        file.writelines(file_msg)

def encrypt_file(file_name: str) -> None:
    """Encrypt a given file in the working directory.

    Args:
        file_name (str): Name of the plaintext file (without extension) to
        encrypt.

    Returns:
        None

    Raises:
        FileNotFoundError: If the specified file does not exist.
    """

    print("Encrypt file selected.")

    # Read in cleartext message.
    try:
        with open(f"working/{file_name}.txt", "r", encoding="utf-8") as file:
            file_data = file.read()
    except FileNotFoundError:
        print(f"Error: Can not find file {file_name}.")
        return

    # Covert cleartext to bytes.
    data = file_data.encode()

    # Generate 128 bit (16 byte) AES key and save it for later use.
    # TODO: Add encryption for the key as well.
    aes_key = get_random_bytes(16)
    with open(f"working/{file_name}_aes.key", "wb") as file:
        file.write(aes_key)

    # Create AES cipher. OCB mode provides confidentiality and integrity.
    cipher = AES.new(aes_key, AES.MODE_OCB)

    # Encrypt message and authenticate. Cipher tag verifies integrity.
    cipher_text, cipher_tag = cipher.encrypt_and_digest(data)
    assert len(cipher.nonce) == 15

    # Save encrypted message.
    with open(f"working/{file_name}_encrypted.bin", "wb") as file:
        file.write(cipher_tag)
        file.write(cipher.nonce)
        file.write(cipher_text)

def decrypt_file(file_name: str, key_name: str) -> None:
    """Decrypt an encrypted file in the working directory.

    Returns:
        None

    Raises:
        FileNotFoundError: If the AES key or message file does not exist.
        ValueError: If decryption fails due to tampering or invalid
        authentication.
        AssertionError: If required components are not properly loaded or typed.
    """

    print("Decrypt file selected.")

    # Load the AES key.
    try:
        with open(f"working/{key_name}", "rb") as key_file:
            aes_key = key_file.read()
    except FileNotFoundError:
        print("Error: No key file found. Regenerate message.")
        return

    # Load the encrypted file.
    try:
        cipher_tag, cipher_nonce, cipher_text = None, None, None
        with open(f"working/{file_name}", "rb") as file:
            cipher_tag = file.read(16)
            cipher_nonce = file.read(15)
            cipher_text = file.read()
    except FileNotFoundError:
        print("Error: Message file not found. Regenerate message.")
        return

    # Decrypt the file.
    try:
        assert all([aes_key, cipher_tag, cipher_nonce, cipher_text])
    except AssertionError as e:
        print(f"Error: {e}")

    should_save_file = False
    cipher = AES.new(aes_key, AES.MODE_OCB, nonce=cipher_nonce)
    try:
        assert isinstance(cipher_text, bytes)
        assert isinstance(cipher_tag, bytes)
        clear_text = cipher.decrypt_and_verify(cipher_text, cipher_tag)
        print(f"Message: {clear_text.decode()}")
        should_save_file = True
    except AssertionError as e:
        print(f"Error: {e}")
    except ValueError:
        print("Warning: The file was altered! Decrypted message will not be " \
        "saved.")

    # Save decrypted message to file.
    if should_save_file:
        try:
            with open(f"working/{file_name}_decrypted.txt", "wb") as file:
                file.write(clear_text)
        except PermissionError as e:
            print(f"Error: {e}")

def cleanup_files() -> None:
    """Remove any files in working directory.

    Returns:
        None

    Raises:
        OSError: If file removal encounters an error.
    """

    for file in os.listdir("working"):
        try:
            os.remove(f"working/{file}")
        except OSError as e:
            print(f"Error: {e}")

def main():
    """Prompt user and process input.

    Returns:
        None

    Raises:
        OSError: If working directory cannot be created.
    """

    # Create working directory if it does not alread exist.
    try:
        if not os.path.exists("working/"):
            os.makedirs("working")
    except OSError as e:
        print(f"Error: {e}")

    # Welcome user.
    print("\nWelcome to Encrypt-Tool!")

    # Enter main program loop.
    while True:

        # Display menu to the user.
        display_menu()

        # Get the menu choice from user.
        user_input = get_menu_input()

        # Process the menu choice from user.
        if user_input == 1:
            file_name = get_input("Enter file name: ")
            file_msg = get_input("Enter message: ")
            create_file(file_name, file_msg)
        elif user_input == 2:
            file_name = get_input("Enter file name: ")
            encrypt_file(file_name)
        elif user_input == 3:
            file_name = get_input("Enter file name: ")
            key_name = get_input("Enter key name: ")
            decrypt_file(file_name, key_name)
        elif user_input == 4:
            cleanup_files()
        elif user_input == 5:
            break

    # Thank user.
    print("\nThank you for using Encrypt-Tool!\n")

def cli():
    """Hook to main for built project.

    Returns:
        None
    """

    main()

if __name__ == "__main__":
    main()
