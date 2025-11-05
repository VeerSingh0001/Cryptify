from encryption import AESFileEncryptor
from decryption import AESFileDecryptor

def display_encryption_menu():
    """Display the main menu"""
    print("\n" + "="*50)
    print("     AES-256 GCM File Encryption Tool")
    print("="*50)
    print("\n1. Generate new encryption key")
    print("2. Encrypt a file (with existing key)")
    print("3. Encrypt a file (generate new key)")
    print("4. Decrypt a file")
    print("5. Exit")
    print("\n" + "-"*50)

def encrypt():
    encryptor = AESFileEncryptor()
    
    print("\n🔐 Welcome to AES-256 GCM File Encryption Tool")
    
    while True:
        display_encryption_menu()
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            # Generate and save a new key
            print("\n🔑 Generating new encryption key...")
            key = encryptor.generate_key()
            
            key_filename = input("Enter filename to save key (default: encryption_key.key): ").strip()
            if not key_filename:
                key_filename = "encryption_key.key"
            
            encryptor.save_key(key, key_filename)
            print(f"\n   Key (base64): {base64.b64encode(key).decode()}")
            
        elif choice == '2':
            # Encrypt with existing key
            print("\n📂 Encrypt file with existing key")
            
            key_filename = input("Enter key filename (default: encryption_key.key): ").strip()
            if not key_filename:
                key_filename = "encryption_key.key"
            
            key = encryptor.load_key(key_filename)
            if key is None:
                continue
            
            input_file = input("Enter file path to encrypt: ").strip()
            if not input_file:
                print("✗ No file specified.")
                continue
            
            # Generate output filename
            output_file = input(f"Enter output filename (default: {input_file}.encrypted): ").strip()
            if not output_file:
                output_file = f"{input_file}.encrypted"
            
            encryptor.encrypt_file(input_file, output_file, key)
            
        elif choice == '3':
            # Generate new key and encrypt
            print("\n📂 Encrypt file with new key")
            
            input_file = input("Enter file path to encrypt: ").strip()
            if not input_file:
                print("✗ No file specified.")
                continue
            
            # Generate output filename
            output_file = input(f"Enter output filename (default: {input_file}.encrypted): ").strip()
            if not output_file:
                output_file = f"{input_file}.encrypted"
            
            # Generate key
            print("\n🔑 Generating new encryption key...")
            key = encryptor.generate_key()
            
            key_filename = input("Enter filename to save key (default: encryption_key.key): ").strip()
            if not key_filename:
                key_filename = "encryption_key.key"
            
            encryptor.save_key(key, key_filename)
            
            # Encrypt
            encryptor.encrypt_file(input_file, output_file, key)

        elif choice == '4':
            # Decrypt a file
            decryptor = AESFileDecryptor()
            print("\n📂 Decrypt a file")
            
            key_filename = input("Enter key filename (default: encryption_key.key): ").strip()
            if not key_filename:
                key_filename = "encryption_key.key"
            
            key = AESFileEncryptor.load_key(key_filename)
            if key is None:
                continue
            
            input_file = input("Enter file path to decrypt: ").strip()
            if not input_file:
                print("✗ No file specified.")
                continue
            
            # Generate output filename
            output_file = input(f"Enter output filename (default: {input_file}.decrypted): ").strip()
            if not output_file:
                output_file = f"{input_file}.decrypted"
            
            decryptor.decrypt_file(input_file, output_file, key)

        elif choice == '5':
            print("\n👋 Thank you for using AES Encryption Tool!")
            print("   Remember to keep your encryption keys safe!\n")
            break
            
        else:
            print("\n✗ Invalid choice. Please enter 1-4.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    encrypt()