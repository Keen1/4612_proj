import sqlite3 
import psutil
import requests
import sys
import json
import vt
import os
from datetime import datetime
from KeyStore import *
from DbCrawler import *


#netalyzer class
#get network connection data from browswer history or the psutil module
class Netalyzer:
	def __init__(self):
		self.output = []
	
	
		
	def write_URL_Output(self, url, stats):
		self.output.append(f"Analysis stats for {url}\n")
		for title in stats:
			self.output.append(f"{title}: {stats[title]}")
		
		self.output.append("****************\n")
	
	def write_IP_Output(self, title, harmless, mal, susp, undetected):
		self.output.append(title)
		self.output.append(harmless)
		self.output.append(mal)
		self.output.append(susp)
		self.output.append(undetected)
		
		self.output.append("****************\n")
	
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
			

	
	#scan a url or ip address in virustotal
	def vt_Scan(self, url=None, ip=None):
		#get the key
		
		#if key is none something went wrong

		with requests.Session() as session:

			#if we are getting info about a url we can use the vt api function provided
			if url:
				ks = KeyStore()
				key = ks.get_API_Key()
				if not key:
					print("Erroy when attempting to access VirusTotal api key.")
					sys.exit()

				client = vt.Client(key.decode())
				url_id = vt.url_id(url)
				urlObj = client.get_object("/urls/{}", url_id)
				
				self.write_URL_Output(url, urlObj.last_analysis_stats)
				client.close()
			#vt doesn't provide a function for ip scans like it does for urls.
			#need to post a request and then parse the json
			if ip:
				ks = KeyStore()
				url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
				headers = {
					"accept": "application/json",
					"x-apikey": f"{ks.get_API_Key()}"}
				response = session.get(url, headers=headers)
				
				jsonDat = json.loads(response.text)
				lastAnalysisStats = jsonDat["data"]["attributes"]["last_analysis_stats"]
				#format to write
				titleStr = f"Last Analysis Stats\n"
				harmlessStr = f"Harmless: {lastAnalysisStats['harmless']}\n"
				malStr = f"Malicious: {lastAnalysisStats['malicious']}\n"
				suspStr = f"Suspicious: {lastAnalysisStats['suspicious']}\n"
				undetectStr = f"Undetected: {lastAnalysisStats['undetected']}\n" 
				#write the output
				self.write_IP_Output(titleStr, harmlessStr, malStr, suspStr, undetectStr)




