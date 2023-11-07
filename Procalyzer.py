import os
import psutil
from datetime import datetime

#procalyzer class
#collects information about processes running on the system

class Procalyzer:
	#constructor
	def __init__(self):
		self.outputs = []
	
	#format and append log data for a process to the outputs list	
	def format_Outputs(self, process_info, open_files, remote_conns):
		#process name
		pName = process_info["name"]
		name = f"Name: {pName}\n"
		self.outputs.append(name)
		
		#process id
		procID = process_info["pid"]
		pid = f"pid: {procID}\n"
		self.outputs.append(pid)
		
		#username for user running process
		uName = process_info["username"]
		username = f"Username: {uName}\n"
		self.outputs.append(username)
		
		#time the process was created
		cTime = process_info["create_time"]
		cTime = datetime.fromtimestamp(cTime).strftime('%Y-%m-%d %H:%M:%S')
		timeCreated = f"Time created: {cTime}\n"
		self.outputs.append(timeCreated)
		
		#exectuable that started the process
		exe = process_info["exe"]
		executable = f"Executable: {exe}\n"
		self.outputs.append(executable)

		self.outputs.append("Open files: \n")
		
		#files that the process is accessing
		for fp in open_files:
			self.outputs.append(fp)
		self.outputs.append("\nRemote Connections: \n")
		
		#remote connections the process is making
		for remConn in remote_conns:
			self.outputs.append(remConn)

		self.outputs.append("******************************\n")
		self.outputs.append("******************************\n")
	
	#get the output for the processes running on the system
	def get_Proc_Outputs(self):
		return self.outputs
	#run function
	def run(self):
		self.get_Usr_Procs()

	#get a list of all the user processes running on the system
	def get_Usr_Procs(self):
		
		#iterate through the process iterator
		print("collecting process logs. This might take a minute.") 
		for proc in psutil.process_iter():
			#try catch for pulling process info
			try:
				process_info = proc.as_dict()

				openFiles = process_info["open_files"]
				open_file_list = []
				
				if openFiles:
					for line in openFiles:
						open_file_list.append(line[0])
				
				connections = process_info["connections"]
				remote_conns = []
				for conn in connections:
					if len(conn.raddr) > 0:
						
						ip = conn.raddr.ip
						port = conn.raddr.port
						connStr = f"IP: {ip}, port: {port}\n"
						remote_conns.append(connStr)
				
				self.format_Outputs(process_info, open_file_list, remote_conns)	


				
			except(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
				print("Unable to access process.")

		print("process collection complete. ")
		
	


		

	

	

	