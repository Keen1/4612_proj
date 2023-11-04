import os
from cryptography.fernet import Fernet
import getpass
class KeyStore:
	def __init__(self):
		self.ENV_VAR = 'VT_KEY'

	def get_API_Key(self):
		pk = getpass.getpass("Enter your private key: ")
		cipher = Fernet(pk.encode())
		return cipher.decrypt(os.environ[f"{self.ENV_VAR}"])
		



