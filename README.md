# 4612_proj
## A simple cli incident response system.
This program is academic in nature and should not be used as a commercial product. 

This program was designed for data collection on windows systems.

You can run this program in your own virtual environment, just follow these steps:
1. download the src code from this repo including the requirements.txt file.
2. create a new virtual environment in the directory of your choice. This project uses the py -m venv [env_name] package.
3. Activate your virtual environment. This can be done by navigating to the Scripts directory and executing the Activate.ps1 script. 
4. run pip install -r path/to/requirements.txt to install the required dependencies.
5. You should be ready to go!

It should be noted that the handling of the API key has room for improvement. Currently, to use the virustotal api scanning functionality you must:

1. Encrypt your api key with the cryptography module using Fernet.
2. Save your private key somewhere safe like a password manager. Keepass is a free and robust solution.
3. Place your encrypted api key into an environment variable named 'VT_KEY'

A KeyGen.py script is included to simplify this process. Simply place your key into the script, encrypt it, and you are ready to store the encrypted key as environment variable. DO NOT leave your key in plaintext in this script. That is insecure. Do not forget to save your private key as well. 

Once these steps are taken you will be able to provide your private encryption key to decrypt the api key for use.
The VirusTotal API is a REST api with json responses. When using the -si or -su commands, you do not need to provide an output path to save the full json response. Doing so will not work. The full json is saved to a file in the directory with an obvious naming convention and preliminary results are shared via stdout. It should be noted this design also has room for improvement. Plans to provide your own path to save the json are in development.

It should also be noted that running without any options will run a default configuration, which will produce a large amount of output. It is not recommended to do this without the -o option to push output to a file. 



  
