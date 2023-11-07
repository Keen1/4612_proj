from KeyStore import *
import requests
import json
import sys

#vt scanner class
#scans either an ip or an url and returns the associated stats

class VtScanner:
	
	
	#get stats relating to an ip
	def get_Ip_Stats(self, ip):
		jsonPath = "vtIpScan.json"
		#prompt for api key
		ks = KeyStore()
		key = ks.get_API_Key()
		#url for api ip_addresses endpoint
		url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
		#set the headers of the request
		headers = {
		"accept": "application/json",
		"x-apikey": f"{key.decode()}" }
		#try the quest
		try:
			#get the response
			response = requests.get(url, headers=headers)
			#load the json
			responseData = json.loads(response.text)
			#pull the last analysis stats
			ipStats = responseData['data']['attributes']['last_analysis_stats']
			#write the preliminary stats
			titleStr = f"Analysis stats for ip: {ip}\n"
			self.write_Prelim_Data(titleStr, ipStats)
			#write the full json to a file
			
			self.write_Full_Json(responseData, jsonPath)
			print(f"Successfully wrote json to {jsonPath}")
		#catch
		except requests.exceptions.RequestException as e:
			print("Something went wrong when requesting the resource.")
			print(f"resource: {url}")
			print(e)
			sys.exit()

	#get stats relating an url
	#Note - this requires two requests
	# 1) First request to get the specific url for the unique url id
	# 2) Query the api based on that unique url-id
	# TODO - Format the url to generate the url_id and reduce requests by 1
	def get_Url_Stats(self, url):
		jsonPath = "vtUrlScan.json"
		#prompt for api key
		ks = KeyStore()
		key = ks.get_API_Key()
		#url for api urls endpoint
		urlStr = "https://www.virustotal.com/api/v3/urls"
		#set the payload
		payload = {"url": f"{url}"}
		#set the headers
		headers = {
			"accept": "application/json",
			"x-apikey": f"{key.decode()}",
			"content-type": "application/x-www-form-urlencoded"
		}
		
		try:
			#try to get the response
			response = requests.post(urlStr, data=payload, headers=headers)
			

			if response:
				#load the json
				responseData = json.loads(response.text)
				#pull the analysis url
				analysisUrl = responseData['data']['links']['self']

				#get the analysis based on the unique url id
				headers = {
					"accept": "application/json",
					"x-apikey": f"{key.decode()}"
				}
				#get the final response
				finResponse = requests.get(analysisUrl, headers=headers)
				#load the json
				finResponseData = json.loads(finResponse.text)
				#get the url stats
				urlStats = finResponseData['data']['attributes']['stats']
				
				#write prelim results to console
				titleStr = f"Analysis stats for {url}\n"
				self.write_Prelim_Data(titleStr, urlStats)
				#write the full json to a file
				
				self.write_Full_Json(finResponseData, jsonPath)
				print(f"Successfully wrote json to {jsonPath}")

			else:
				print("Error.")
		#catch
		except requests.exceptions.RequestException as e:
			print("something went wrong when requesting the resource")
			print(f"resource {url}")
			print(e)
			sys.exit()
	
	#write the prelim results to console
	def write_Prelim_Data(self, title, stats):
		print("Preliminary output: ")
		print(title)
		print(stats)
	#output the full json response to a file
	def write_Full_Json(self, jsonObj, path):
		path = path.strip("//")
		with open(path, "w") as file:
			json.dump(jsonObj, file, indent=4)






