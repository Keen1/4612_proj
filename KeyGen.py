from cryptography.fernet import Fernet


# Generate a random Fernet key
key = Fernet.generate_key()
print(key)

# Create a Fernet cipher object with the key

cipher = Fernet(key)

#put your key here
apiKey = "your_key_here"





# Encrypt the API key
encKey = cipher.encrypt(apiKey.encode())
print(f"Encrypted API KEY: {encKey}")
print(f"PRIVATE KEY: {key}")
print(f"Save your private key somehwere safe! You will need it to decrypt the api key for use.")


 