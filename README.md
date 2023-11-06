# 4612_proj
A simple cli incident response system 
This program is academic in nature and should not be used as a commercial product. 

This program was designed to be compiled into an exe using the pyinstaller module. It is currently only intended for use on windows systems.  

It should be noted that the handling of the API key has room for improvement. Currently, to use the virustotal api scanning functionality you must:

1. Encrypt your api key with the cryptography module using Fernet.
2. Save your private key somewhere safe like a password manager. Keepass is a free and robust solution.
3. Place your encrypted api key into an environment variable named 'VT_KEY'

Once these steps are taken you will be able to provide your private encryption key to decrypt the api key for use. 

It should also be noted that running without any options will run a default configuration, which will produce a large amount of output. It is not recommended to do this without the -o option to push output to a file. 


  
