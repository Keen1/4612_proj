import sqlite3 
import psutil
import sys
import os
from datetime import datetime
from DbCrawler import *



#netalyzer class
#get network connection data from browswer history or the psutil module
class Netalyzer:
	def __init__(self):
		self.output = []
	
	def write_Browser_Output(self, browserHistList):
		for item in browserHistList:
			self.output.append(item)
		
		
	def write_Netcon_Output(self, family, cType, laddr, raddr):

		self.output.append(family)
		self.output.append(cType)
		self.output.append(laddr)
		self.output.append(raddr)
		
		self.output.append("****************\n")

	def get_Output(self):
		return self.output



#explore the browser history of the machine(sqlite3 db path required[global var])
	def explore_Browser_History(self):
		

		entries = []
		
		#create a db crawler to search for databases
		crawler = DbCrawler()
		paths = crawler.find_Browser_History_Databases(os.path.expanduser('~'))
		#try to connect to each of the db paths found
		for path in paths:
			print(f"Collecting browser history from: {path}")
			
			try:

				connection = sqlite3.connect(path)
				cursor = connection.cursor()

				#pull data from the db
				#depending on the browser the db schema will differ
				#browser history in mozilla db is stored in moz_places
				#browser history in chrome and edge are stored in urls table
				if "Firefox" in path:
					
					cursor.execute("SELECT url, title, visit_count FROM moz_places")
					entries = cursor.fetchall()
				
				elif "Chrome" in path or "Edge" in path:
					cursor.execute("SELECT url, title, visit_count FROM urls")
					entries = cursor.fetchall()


			except sqlite3.Error:
				print("An error occurred when trying to access db:")
				print(path)

			#TODO - expand class to output to std or to a file given a path
			if len(entries) == 0:
				print(f"No browser history found in {path} database.")
			else:

				
				pathStr = f"BROWSER HISTORY FROM :  {path}\n"
				browserHistList = []
				browserHistList.append("********************\n")
				browserHistList.append("********************\n")
				browserHistList.append(pathStr)
				browserHistList.append("********************\n")
				browserHistList.append("********************\n")
				
				
				

				for entry in entries:
					url, title, visitCount  = entry
					if visitCount == 0:
						continue
					url = f"URL: {url}\n"
					title = f"Title: {title}\n"
					visitCount = f"Visit count: {visitCount}\n"
					browserHistList.append(url)
					browserHistList.append(title)
					browserHistList.append(visitCount)
					browserHistList.append("****************\n")

				self.write_Browser_Output(browserHistList)


				

	#explore the network history of current processes on the machine 
	def explore_Net_History(self):
		#get connections from the psutil library
		connections = psutil.net_connections(kind='inet')

		#print data from the connections
		#TODO - expand class to output to std to a file given a path
		for conn in connections:
			famStr = f"Family: {conn.family}\n"
			typeStr = f"Type: {conn.type}\n"
			laddr = f"Local Address: {conn.laddr}\n"
			raddr = f"Remote Address: {conn.raddr}\n"
			self.write_Netcon_Output(famStr, typeStr, laddr, raddr)
			

	



