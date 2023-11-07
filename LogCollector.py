#script that pulls windows security event logs
"""
proof of conecpt 
"""
import win32evtlog
EVENT_IDS = [4624, #successful logon
				4625, #failed login attempts
				4634, #account logoff
				4647, #user initiated logoff
				4648, #a logon attempt w/ explicit credentials
				4720, #user account creation
				4722, #user account enabled
				4725, #user account disabled
				4726, #user account deleted
				4732, #member added to a security-enabled local group
				4733, #member removed from securrity-enabled local-group
				4672, #special priv assigned to new logon
				4673, #privileged service called
				4674, #op attempted on privileged object
				4656, #handle to object requested
				4660, #object deleted
				4658, #handle to an object was closed
				4688, #process creations
				4689, #process exit
				4719, #system audit policy changed
				4716, #trusted domain info modified
				4616, #system time changed
				4680, #object deleted
				4727, #security-enabled global group created
				4728, #member added to a security-enabled global group
				4729, #member removed from a security-enabled global group
				4730, #security-enabled global group deleted
				4731, #security-enabled local group created
				4734, #member added to a security-enabled local group
				4735, #member removed from security-enabled local group
				4737] #security-enabled local group deleted
class LogCollector:
	def __init__(self):
		self.eventOutputs = []

	def format_Output(self, evtID, eventType, eventMessage, evtSrc):
		result = f"Event type: {eventType}\n"
		result += f"Event ID: {evtID}\n"
		result += f"Event Message: {eventMessage}\n"
		result += f"Source: {evtSrc}\n"
		
		self.eventOutputs.append(result)

	def get_Evt_Outputs(self):
		return self.eventOutputs

	#run the event collector
	def run(self, specID=None):
		
		try:
			#log type to be collected
			logType = 'Security'
			#get the event log handle
			logHandle = win32evtlog.OpenEventLog(None, logType)

			#event flags
			flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
			#number of events
			eventCount = win32evtlog.GetNumberOfEventLogRecords(logHandle)
			#get events 
			events = win32evtlog.ReadEventLog(logHandle, flags, 0)
			
			#event types			
			eventTypeDesc = {
				win32evtlog.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
				win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Audit Success"
			}
			#if events were in the event log
			if events:
				for event in events:
					
					if specID is None:

						if event.EventID  in EVENT_IDS:
							
							evtID = event.EventID
							eventType = eventTypeDesc.get(event.EventType, "Unknown type")
							eventMessage = event.StringInserts
							
							evtSrc = event.SourceName
							#pass the event details to the output format function
							self.format_Output(evtID, eventType, eventMessage, evtSrc)
							
							
					#if a specific event id was specified by the user
					if specID is not None:

						if event.EventID == specID:
							evtID = event.EventID
							eventType = eventTypeDesc.get(event.EventType, "Unknown type")
							eventMessage = event.StringInserts
							
							evtSrc = event.SourceName
							self.format_Output(evtID, eventType, eventMessage, evtSrc)


			
		except win32evtlog.error as e:
			print(f"Error accessing the event log: {e}")
		finally:
			if logHandle:
				win32evtlog.CloseEventLog(logHandle)			


