import argparse
import validators
import ipaddress
import sys
import re
from Procalyzer import *
from Netalyzer import *
from LogCollector import *

#driver

#define the arg parser and return it
def init_Parser():
	#initialize the parser
	parser = argparse.ArgumentParser(
						prog='IRSys',
						description='An incident response system that collects endpoint artifacts for analysis')
	#events option
	parser.add_argument("-e", '--events', dest="events", action="store_true",
		help="Pull event logs.")
	#additional specification for a particular event id
	parser.add_argument("--event-id", dest="event_id", type=int, 
		help="Specify an event id to search for.")
	#processes argument
	parser.add_argument("-p", "--processes", action="store_true", 
		help="Collect a list of running processes.")
	#connections arugment
	parser.add_argument("-n", "--net", action="store_true", help="Collect network connection data.")
	parser.add_argument("-b", "--browser", action="store_true", help="Collect browser history data.")

	#scanning arguments
	parser.add_argument("-si", "--scanip", nargs=1, help="Scan an ip address using the virustotal api" )
	parser.add_argument("-su", "--scanurl", nargs=1, type=str, help="Scan a url using the virustotal api")
	#output path argument
	parser.add_argument("-o", "--output", type=str, help="Specify an output file.")
	#return the parser
	return parser

#validate a url
def valid_URL(url):
	if not url.startswith(('http://', 'https://')):
		url = 'http://' + url

	if validators.url(url):
		return True
	else:
		return False

#validate an ip address
def valid_IP(ip):
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		return False

#handle output
def handle_Output(output,  path=None):
	#if the path is not none the user wants output to a file
	if path is not None:
		with open(path, 'w') as file:
			for line in output:
				line = re.sub(r'[^\x00-\x7F]+', '?', line)
				file.write(line)
		file.close()
		
	#standard output
	if path is None:
		for line in output:
			print(line)

		
def run_Default():
	print("Running default configuration. This may take a while...")
	print("Collecting event logs...")
	#start the log collector
	logColl = LogCollector()
	logColl.run()
	evtOut = logColl.get_Evt_Outputs()
	#handle the output
	handle_Output(evtOut,outPath)
	
	print("Collecting process data...")
	#start the procalyzer
	plyzer = Procalyzer()
	plyzer.run()
	pOut = plyzer.get_Proc_Outputs()
	handle_Output(pOut, outPath)
	
	print("Collecting connection data...")
	#start the netalyzer
	nlyzer = Netalyzer()
	nlyzer.explore_Browser_History()
	nlyzer.explore_Net_History()
	nOut = nlyzer.get_Output()
	handle_Output(nOut, outPath)
	print("Data collection finished.")
	
	sys.exit()


#main
if __name__ =="__main__":
	#intialize the parser
	parser = init_Parser()
	#get the arguments
	args = parser.parse_args()
	
	outPath = None
	#check if an output file was provided
	if args.output:
		outPath = args.output
		print(f"path {outPath} collected for processing.")
	
	if not (args.events or args.processes or args.net or args.browser or args.event_id or args.scanip or args.scanurl):
		run_Default()
		
	else:
		#check for different args used
		if args.events:
			print("Collecting event logs...")
			logColl = LogCollector()
			logColl.run()
			output = logColl.get_Evt_Outputs()
			print(output)
			handle_Output(output, outPath)
		
		if args.event_id:
			print(f"Collecting logs for event-id {args.event_id}...")
			#run the logcollector and handle the output
			logColl = LogCollector()
			logColl.run(args.event_id)
			output = logColl.get_Evt_Outputs()
			handle_Output(output, outPath)
			
		#process flag used
		if args.processes:
			print("Collecting running processes...")
			plyzer = Procalyzer()
			plyzer.run()
			output = plyzer.get_Proc_Outputs()
			handle_Output(output, outPath)
		#net flag was used
		if args.net:
			nalyzer = Netalyzer()
			nalyzer.explore_Net_History()
			nOut = nalyzer.get_Output()
			handle_Output(nOut, outPath)
		#browser flag was used
		if args.browser:
			balyzer = Netalyzer()
			balyzer.explore_Browser_History()
			bOut = balyzer.get_Output()
			handle_Output(bOut, outPath)

		#scan url flag used
		if args.scanurl:
			urlAddr = args.scanurl[0]
			
			if not valid_URL(urlAddr):
				print("Malformed URL, enter a valid URL to scan.")
				sys.exit()
			else:
				nalyzer = Netalyzer()
				nalyzer.vt_Scan(url=urlAddr)
				scanOutput = nalyzer.get_Output()
				handle_Output(scanOutput, outPath)
		
		#scan ip flag used	
		if args.scanip:
			ipAddr = args.scanip[0]

			if not valid_IP(ipAddr):
				print("Malformed IP address, enter a valid IP address to scan.")
				sys.exit()
			else:
				nalyzer = Netalyzer()
				nalyzer.vt_Scan(ip=ipAddr)
		