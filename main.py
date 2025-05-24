
def display_menu():
    """Display the menu to user in the CLI."""
    
    display_menu.options = [
        "Create a file.",
        "Encrypt a file.",
        "Decrypt a file.",
        "Exit."
    ]
    
    print()
    for i, txt in enumerate(display_menu.options):
        print(f"{i+1}: {txt}")

def sanitize(txt):
    INVALID_CHARS = [';', '|', '&', "\"", "\'"]
    return "".join([i for i in str(txt) if not i in INVALID_CHARS])



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

    raw = int
    try:
        # Get input from user. 
        raw = int(input("Select option: ").strip())
        raw = int(sanitize(raw))

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

def encrypt_file():
    print("Encrypt file selected.")

def decrypt_file():
    print("Decrypt file selected.")

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
            break

    # Thank user. 
    print("\nThank you for using Encrypt-Tool!\n")

if __name__ == "__main__":
    main()
