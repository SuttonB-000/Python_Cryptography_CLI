import base64
import binascii
import os

from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# Fernet Functions

FERNET_KEY_FILE = Path('fernet.key')

def generate_fernet_key():
    '''Create a Fernet key without overwriting an existing key.'''
    key = Fernet.generate_key()

    try:
        with FERNET_KEY_FILE.open('xb') as key_file:
            key_file.write(key)
    except FileExistsError:
        print(f"Key file already exist: {FERNET_KEY_FILE}")
        print('Keep existing key to decrypt messages made with it.')
    except OSError as error:
        print(f'Could not save the key: {error}')
    else:
        print(f'Fernet key saved to {FERNET_KEY_FILE}')
        print('Keep this file secret and back it up')


def load_fernet():
    '''Load the saved key and return a FERNET instance, or None'''
    
    try:
        key = FERNET_KEY_FILE.read_bytes()
        return Fernet(key)
    except FileNotFoundError:
        print(f'Key file is not found: {FERNET_KEY_FILE}')
        print('Generate a new key first')
    except ValueError:
        print(f'Invalid fernet key presented: {FERNET_KEY_FILE}')
    except OSError as error:
        print(f'Could not read the key: {error}')

    return None

def encrypt_fernet():
    fernet = load_fernet()
    if fernet is None:
        return

    plaintext = input('Enter text to encrypt (under 100 characters): ')
    if len(plaintext) >= 100:
        print('Length must be below 100 characters')
        return

    token = fernet.encrypt(plaintext.encode('utf-8'))
    print('Ciphertext')
    print(token.decode('ascii'))

def decrypt_fernet():
    fernet = load_fernet()
    if fernet is None:
        return

    token = input('Enter the Fernet Ciphertext: ').strip()

    try:
        plaintext_bytes = fernet.decrypt(token.encode('ascii'))
        plaintext = plaintext_bytes.decode('utf-8')
    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError):
        print('Decryption failed, Check the ciphertext and key')
        return

    print('Plaintext: ')
    print(plaintext)

#RSA (asymmetric) functions
RSA_PRIVATE_KEY = Path('rsa_private.pem')
RSA_PUBLIC_KEY_FILE = Path('rsa_public.pem')

def generate_rsa_keys():
#Create an RSA key pair without overwriting existing files.
    if RSA_PRIVATE_KEY.exists() or RSA_PUBLIC_KEY_FILE.exists():
        print('An RSA key already exists, no new keys generated')
        print('Keep both existing files together to perserve the key pair.')
        return
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size= 2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    try:
    #create the private file exclusively, with owner-only permissions
    # on systems that support Unix file permissions
        descriptor = os.open(
            RSA_PRIVATE_KEY,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, 'wb') as key_file:
            key_file.write(private_pem)

        with RSA_PUBLIC_KEY_FILE.open('xb') as key_file:
            key_file.write(public_pem)

    except OSError as error:
        print(f'Could not save the RSA key pair: {error}')
        print('A key file may have been created. inspect the files before retrying')
        return

    print(f'Private key saved to {RSA_PRIVATE_KEY}')
    print(f'Public key saved to {RSA_PUBLIC_KEY_FILE}')
    print('Keep the private key secret and back it up')

def load_rsa_public_key():
    try:
        key = serialization.load_pem_public_key(RSA_PUBLIC_KEY_FILE.read_bytes())
        if not isinstance(key, rsa.RSAPublicKey):
            print("The public key file does not contain an RSA public key.")
            return None
        return key
    except FileNotFoundError:
        print(f"Public key file not found: {RSA_PUBLIC_KEY_FILE}")
    except (ValueError, TypeError, UnsupportedAlgorithm):
        print("Could not load the RSA public key. Check the file format.")
    except OSError as error:
        print(f"Could not read the public key: {error}")

    return None

def load_rsa_private_key():
    try:
        key = serialization.load_pem_private_key(
            RSA_PRIVATE_KEY.read_bytes(),
            password=None,
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            print("The private key file does not contain an RSA private key.")
            return None
        return key
    except FileNotFoundError:
        print(f"Private key file not found: {RSA_PRIVATE_KEY}")
    except (ValueError, TypeError, UnsupportedAlgorithm):
        print("Could not load the RSA private key. Check the file format.")
    except OSError as error:
        print(f"Could not read the private key: {error}")

    return None

def rsa_oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

def encrypt_rsa():
    public_key = load_rsa_public_key()
    if public_key is None:
        return

    plaintext = input("Enter plaintext (fewer than 100 characters): ")
    if len(plaintext) >= 100:
        print("Plaintext must be fewer than 100 characters.")
        return

    plaintext_bytes = plaintext.encode("utf-8")

    # OAEP with SHA-256 reserves 2 * 32 + 2 bytes.
    key_bytes = (public_key.key_size + 7) // 8
    max_bytes = key_bytes - 2 * hashes.SHA256().digest_size - 2

    if len(plaintext_bytes) > max_bytes:
        print(
            f"Message uses {len(plaintext_bytes)} UTF-8 bytes; "
            f"this RSA key allows at most {max_bytes} bytes."
        )
        return

    try:
        ciphertext = public_key.encrypt(plaintext_bytes, rsa_oaep_padding())
    except ValueError:
        print("Encryption failed. Check the public key and message size.")
        return

    print("Ciphertext:")
    print(base64.b64encode(ciphertext).decode("ascii"))

def decrypt_rsa():
    private_key = load_rsa_private_key()
    if private_key is None:
        return

    text = input("Enter the RSA ciphertext: ").strip()

    try:
        ciphertext = base64.b64decode(text.encode("ascii"), validate=True)
        plaintext_bytes = private_key.decrypt(ciphertext, rsa_oaep_padding())
        plaintext = plaintext_bytes.decode("utf-8")
    except (UnicodeEncodeError, binascii.Error, ValueError, UnicodeDecodeError):
        print("Decryption failed. Check the ciphertext and private key.")
        return

    print("Plaintext:")
    print(plaintext)

def choose_method():
    '''Ask for which encryption to use'''
    while True:
        print('\nChoose an Encryption Method:')
        print('1. Symmetric (Fernet)')
        print('2. Asymmetric (RSA)')
        print('3. Return to main menu')

        choice = input("> ").strip()

        if choice == "1":
            return 'fernet'
        if choice == "2":
            return 'rsa'
        if choice == '3':
            return None

def main():
    actions = {
        ("1", "fernet"): generate_fernet_key,
        ("2", "fernet"): encrypt_fernet,
        ("3", "fernet"): decrypt_fernet,
        ("1", "rsa"): generate_rsa_keys,
        ("2", "rsa"): encrypt_rsa,
        ("3", "rsa"): decrypt_rsa,
    }

    while True:
        print("\nEncryption tool")
        print("1. Generate keys")
        print("2. Encrypt a string")
        print("3. Decrypt a string")
        print("4. Quit")

        action = input("> ").strip()

        if action == "4":
            print("Goodbye!")
            break

        if action not in {"1", "2", "3"}:
            print("Please enter 1, 2, 3, or 4.")
            continue

        method = choose_method()
        if method is None:
            continue

        operation = actions[(action, method)]
        operation()



if __name__ == "__main__":
    main()
