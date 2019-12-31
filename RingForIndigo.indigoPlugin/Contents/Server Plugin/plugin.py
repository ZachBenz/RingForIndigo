#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2019, Zach Benz, All rights reserved.
# https://github.com/ZachBenz/RingForIndigo

import indigo

import datetime
import pytz
import requests
import subprocess
from ring_doorbell import Ring

# Note the "indigo" module is automatically imported and made available inside
# our global name space by the host process.

################################################################################
# Plugin SDK Documentation: https://wiki.indigodomo.com/doku.php?id=indigo_7.4_documentation:plugin_guide
class Plugin(indigo.PluginBase):
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super(Plugin, self).__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get(u"printDebugInEventLog", False)
		self.ring = None
		self.dateFormatString = '%Y-%m-%d %H:%M:%S %Z'   # TODO: Really a constant, move to a const.py or equivalent?
		self.activeButtonPushedTriggers = {}
		self.activeMotionDetectedTriggers = {}
		self.activeDownloadCompleteTriggers = {}
		# TODO: Initialize some tables mapping Indigo devices to Ring devices to make lookups more efficient?


	########################################
	def __del__(self):
		indigo.PluginBase.__del__(self)


	########################################
	def startup(self):
		self.debugLog(u"Startup called")


	########################################
	def shutdown(self):
		# Cleanup handled in runConcurrentThread's self.stopThread exception handling
		self.debugLog(u"Shutdown called")


	########################################
	def makeConnectionToRing(self, username, password):
		# Validate username and password
		if ((username is None) or (username == "")):
			self.debugLog(u"No username specified in plugin configuration; aborting connection attempt")
			return
		if ((password is None) or (password == "")):
			self.debugLog(u"No password specified in plugin configuration; aborting connection attempt")
			return

		# Close any existing connection
		self.closeConnectionToRing()

		# Attempt to connect
		try:
			self.debugLog(u"Attempting to connect to Ring.com API and login as %s" % username)
			self.ring = Ring(username, password)
		except requests.exceptions.HTTPError as exception:
			self.debugLog(u"Caught HTTPError in startup: %s" % (exception))
			if (exception.response.status_code == 401):
				# TODO: Handle status code 401 - perhaps dial back request timing
				self.debugLog(u"401 - Unauthorized")
			elif (exception.response.status_code == 429):
				# TODO: Handle status code 429 - perhaps dial back request timing
				self.debugLog(u"429 - Too Many Requests")

		if (self.isConnected() is True):
			# Connection successful
			self.debugLog(u"Connection to Ring.com API successful")
		else:
			# Connection failed
			self.debugLog(u"Connection to Ring.com API failed")


	########################################
	def closeConnectionToRing(self):
		if ((self.ring is not None) and (self.ring.is_connected is True)):
			self.ring.session.close()


	########################################
	def isConnected(self):
		return ((self.ring is not None) and (self.ring.is_connected is True))


	########################################
	# If runConcurrentThread() is defined, then a new thread is automatically created
	# and runConcurrentThread() is called in that thread after startup() has been called.
	#
	# runConcurrentThread() should loop forever and only return after self.stopThread
	# becomes True. If this function returns prematurely then the plugin host process
	# will log an error and attempt to call runConcurrentThread() again after several seconds.
	######################
	def runConcurrentThread(self):
		try:
			while True:
				# Check to see if our connection to the Ring.com API is up
				self.debugLog(u"Connected to Ring.com API?: %s" % (self.isConnected()))
				if (self.isConnected() is False):
					# Connection is not currently up, attempt to establish connection
					if (('username' in self.pluginPrefs) and ('password' in self.pluginPrefs)):
						self.makeConnectionToRing(self.pluginPrefs['username'], self.pluginPrefs['password'])
					else:
						self.debugLog(u"pluginPrefs do not yet have username and/or password field")

				# If we are connected, update events and device status (otherwise, wait until after sleep to try again)
				if (self.isConnected() is True):
					self.debugLog(u"Getting updates from Ring.com API")

					# Go through and clear motion sensed on all devices each update cycle
					# TODO: Consider having a different update frequency for clearing motion sensed state
					for indigoDevice in indigo.devices.iter("self.doorbell"):
						indigoDevice.updateStateOnServer("onOffState", False)
						indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.MotionSensor)

					# Doorbells
					for ringDevice in self.ring.doorbells:
						# Check to see if this ringDevice is mapped to an Indigo device, otherwise ignore it
						indigoDevice = self.getExistingIndigoDeviceMappingForRingDevice(ringDevice, "doorbell")
						if (indigoDevice is not None):
							# Get latest state and events for this Ring device
							ringDevice.update()

							# Keep track of updated device states
							keyValueList = []
							keyValueList.append({'key': 'ringDeviceName', 'value': ringDevice.name})
							keyValueList.append({'key': 'ringDeviceId', 'value': ringDevice.account_id})
							keyValueList.append({'key': 'ringDeviceLocation', 'value': ringDevice.address})
							keyValueList.append({'key': 'ringDeviceModel', 'value': ringDevice.model})
							keyValueList.append({'key': 'ringDeviceFamily', 'value': ringDevice.family})
							keyValueList.append({'key': 'ringDeviceFirmware', 'value': ringDevice.firmware})
							keyValueList.append({'key': 'ringDeviceBatteryLevel', 'value': ringDevice.battery_life})
							keyValueList.append({'key': 'ringDeviceVolume', 'value': ringDevice.volume})
							keyValueList.append({'key': 'ringDeviceTimezone', 'value': ringDevice.timezone})
							keyValueList.append({'key': 'ringDeviceWifiMACAddress', 'value': ringDevice.id})
							keyValueList.append({'key': 'ringDeviceWifiNetwork', 'value': ringDevice.wifi_name})
							keyValueList.append({'key': 'ringDeviceWifiSignalStrength',
												 'value': ringDevice.wifi_signal_strength})

							# Check for an active alert (only applies to doorbot type Ring devices)
							if ((ringDevice.family == "doorbots") and (ringDevice.check_alerts())):
								# TODO: I don't think this Ring.com API call is per device - rather, global, so
								#  doesn't make sense to call on each device, does it?
								alert = ringDevice.alert
								self.debugLog("Processing an active %s alert" % (alert["kind"]))
								if (ringDevice.account_id == alert["doorbot_id"]):
									# Alert active, so event time is now (approximately, within update frequency)
									now = datetime.datetime.now(tz=pytz.utc)
									stringifiedTime = datetime.datetime.strftime(now, self.dateFormatString)
									keyValueList.append({'key': 'lastEventTime', 'value': stringifiedTime})
									keyValueList.append({'key': 'lastEventId', 'value': alert["id"]})
									keyValueList.append({'key': 'lastEventKind', 'value': alert["kind"]})

									if (alert["kind"] == "ding"):
										keyValueList.append({'key': 'lastDoorbellPressTime', 'value': stringifiedTime})
										
										# Check for triggers we need to execute
										for triggerId, trigger in sorted(self.activeButtonPushedTriggers.iteritems()):
											triggerIndigoDeviceId = trigger.pluginProps.get("indigoDeviceId", "")
											if ((triggerIndigoDeviceId == "-1") or
													(triggerIndigoDeviceId == str(indigoDevice.id))):
												indigo.trigger.execute(trigger)
									elif (alert["kind"] == "motion"):
										keyValueList.append({'key': 'lastMotionTime', 'value': stringifiedTime})
										keyValueList.append({'key': 'onOffState', 'value': True})
										indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.MotionSensorTripped)

										# Check for triggers we need to execute
										for triggerId, trigger in sorted(self.activeMotionDetectedTriggers.iteritems()):
											triggerIndigoDeviceId = trigger.pluginProps.get("indigoDeviceId", "")
											if ((triggerIndigoDeviceId == "-1") or
													(triggerIndigoDeviceId == str(indigoDevice.id))):
												indigo.trigger.execute(trigger)
									else:
										indigo.server.log("SHOULD NOT HAPPEN: Got an alert of kind %s, but didn't"
														  " process it!" % alert["kind"], isError=True)
								else:
									indigo.server.log("SHOULD NOT HAPPEN: Got an alert for a different Ring"
													  " device (%s) than the one we're updating (%s)!" %
													  (alert["doorbot_description"], ringDevice.name), isError=True)

							# Push accumulated state updates to server before processing historical events
							indigoDevice.updateStatesOnServer(keyValueList)

							# Keep track of current state to enable processing event history below
							indigoDeviceLastEventTime = datetime.datetime.strptime(
								indigoDevice.states["lastEventTime"], self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDeviceLastDoorbellPressTime = datetime.datetime.strptime(
								indigoDevice.states["lastDoorbellPressTime"],
								self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDeviceLastMotionTime = datetime.datetime.strptime(
								indigoDevice.states["lastMotionTime"], self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDevicePreviousMostRecentEventTime = indigoDeviceLastEventTime
							indigoDevicePreviousMostRecentEventId = indigoDevice.states["lastEventId"]

							# TODO: Make history limit a heuristic, multiplicative factor of update (sleep) frequency
							# Check for events we haven't processed in history, including things we missed as alerts
							for event in ringDevice.history(limit=10):
								# Skip over event if we already handled it previously
								if (str(event["id"]) == str(indigoDevicePreviousMostRecentEventId)):
									# TODO: What if we missed both a motion a ding alert occurred, but only later
									#  show up in event history - won't we only skip over one of them, resulting
									#  in double processing of the other?
									self.debugLog("Ignoring %s event, already handled it previously" % event["kind"])
									continue

								ringDeviceEventTime = \
									event["created_at"].astimezone(pytz.utc)
								# Process _all_ events newer than the last one we saw last update cycle
								isNewEventToProcess =  indigoDevicePreviousMostRecentEventTime < ringDeviceEventTime
								if isNewEventToProcess:
									self.debugLog("Processing a new event for %s: %s" %
												  (indigoDevice.name, event["kind"]))
									stringifiedTime = datetime.datetime.strftime(ringDeviceEventTime,
																				 self.dateFormatString)
									keyValueList = []
									# Process event if it is newer
									if (indigoDeviceLastEventTime < ringDeviceEventTime):
										indigoDeviceLastEventTime = ringDeviceEventTime
										keyValueList.append({'key': 'lastEventTime', 'value': stringifiedTime})
										keyValueList.append({'key': 'lastEventId', 'value': event["id"]})
										keyValueList.append({'key': 'lastEventKind', 'value': event["kind"]})

									# Process motion and ding kinds to update
									if (event["kind"] == 'motion'):
										# If it was already handled as an alert, this code won't be reached
										if (indigoDeviceLastMotionTime < ringDeviceEventTime):
											indigoDeviceLastMotionTime = ringDeviceEventTime
											keyValueList.append({'key': 'lastMotionTime', 'value': stringifiedTime})
											keyValueList.append({'key': 'onOffState', 'value': True})
											indigoDevice.updateStateImageOnServer(
												indigo.kStateImageSel.MotionSensorTripped)

											# Check for triggers we need to execute
											for triggerId, trigger in sorted(
													self.activeMotionDetectedTriggers.iteritems()):
												triggerIndigoDeviceId = trigger.pluginProps.get("indigoDeviceId", "")
												if ((triggerIndigoDeviceId == "-1") or
														(triggerIndigoDeviceId == str(indigoDevice.id))):
													indigo.trigger.execute(trigger)
									elif (event["kind"] == 'ding'):
										# If it was already handled as an alert, this code won't be reached
										if (indigoDeviceLastDoorbellPressTime < ringDeviceEventTime):
											indigoDeviceLastDoorbellPressTime = ringDeviceEventTime
											keyValueList.append(
												{'key': 'lastDoorbellPressTime', 'value': stringifiedTime})

											# Check for triggers we need to execute
											for triggerId, trigger in sorted(
													self.activeButtonPushedTriggers.iteritems()):
												triggerIndigoDeviceId = trigger.pluginProps.get("indigoDeviceId", "")
												if ((triggerIndigoDeviceId == "-1") or (
														triggerIndigoDeviceId == str(indigoDevice.id))):
													indigo.trigger.execute(trigger)
									# TODO: track on_demand event type?

									# Push accumulated state updates to server
									indigoDevice.updateStatesOnServer(keyValueList)

				# TODO Change to use a user specified update frequency; but, don't let it be less than 5 seconds
				#  or more than X (60?) seconds
				self.sleep(5) # in seconds
		except self.StopThread:
			# Close connection to Ring API
			self.closeConnectionToRing()
			pass


	########################################
	# Actions defined in MenuItems.xml:
	####################
	def printAvailableRingDevices(self):
		indigo.server.log(u"Retrieving all available devices from Ring.com (this may take a moment, please be patient)")
		if self.isConnected():
			for ringDevice in list(self.ring.stickup_cams + self.ring.chimes + self.ring.doorbells):
				ringDevice.update()
				self.printRingDeviceToLog(ringDevice, indigo.server.log)
		else:
			indigo.server.log(u"Connection to Ring.com API down; can't print devices to Event Log")

		indigo.server.log(u"")
		indigo.server.log(u"Done printing available Ring devices to Event Log")
		return


	########################################
	def validatePrefsConfigUi(self, valuesDict):
		# Update debug log print setting
		self.debug = valuesDict.get(u"printDebugInEventLog", False)

		errorDict = indigo.Dict()
		if ((valuesDict["username"] is None) or (valuesDict["username"] == "")):
			errorDict["username"] = "You must specify a username (e.g. janedoe@gmail.com)"
		if ((valuesDict["password"] is None) or (valuesDict["password"] == "")):
			errorDict["password"] = \
				"You must specify a password (sadly, two-factor authentication is not currently supported)"
		if (len(errorDict) > 0):
			return (False, valuesDict, errorDict)

		# Update connection to Ring API based on changes to credentials
		# TODO: Do we really want to do this in the validate function... is there another callback method that
		#  should do it in?
		self.makeConnectionToRing(valuesDict.get("username", None), valuesDict.get("password", None))

		# PluginPrefs will be updated AFTER we exit this method if we say validation was good
		self.debugLog(u"Validated plugin configuration changes")
		return True


	# ########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		if (typeId == "doorbell"):
			if (valuesDict["doorbellDropDownListSelection"] == ""):
				errorDict = indigo.Dict()
				errorDict["doorbellDropDownListSelection"] = \
					"You must pick an available Ring device from the dropdown list"
				return(False, valuesDict, errorDict)
		return True


	########################################
	def validateActionConfigUi(self, valuesDict, typeId, deviceId):
		if (typeId == "downloadVideoAction"):
			errorDict = indigo.Dict()
			if (valuesDict["downloadFilePath"] == ""):
				errorDict["downloadFilePath"] = "You must specify a filename to download video for event to"
			if ((valuesDict["eventIdOption"] == "specifyEventId") and (valuesDict["userSpecifiedEventId"] == "")):
				errorDict["userSpecifiedEventId"] = "You must specify an event ID to download video for"
			if (len(errorDict) > 0):
				return (False, valuesDict, errorDict)
		return True


	########################################
	def validateEventConfigUi(self, valuesDict, typeId, eventId):
		errorDict = indigo.Dict()
		if (valuesDict["indigoDeviceId"] == ""):
			errorDict["indigoDeviceId"] = "You must specify an Indigo device to monitor for events"
		if (len(errorDict) > 0):
			return (False, valuesDict, errorDict)
		return True


	########################################
	def deviceStartComm(self, indigoDevice):
		# Called when communication with the hardware should be started.

		# Initialize onOffState
		keyValueList = []
		keyValueList.append({'key': 'onOffState', 'value': False})

		# Initialize device subModel for newly created Indigo devices
		subModel = indigoDevice.pluginProps.get("selectedRingDeviceModel", "")
		if indigoDevice.subModel != subModel:
			indigoDevice.subModel = subModel
			indigoDevice.replaceOnServer()

		# Initialize lastEventTime, lastDoorbellPressTime, lastMotionTime to date in distant past if needed
		distantPast = datetime.datetime(
			year=1900,
			month=01,
			day=01,
			hour=0,
			minute=0,
			second=0,
			tzinfo=pytz.UTC)
		stringifiedDistantPast = datetime.datetime.strftime(distantPast, self.dateFormatString)

		if ((indigoDevice.states["lastEventTime"] is None) or (indigoDevice.states["lastEventTime"] == "")):
			keyValueList.append({'key': 'lastEventTime', 'value': stringifiedDistantPast})
		if ((indigoDevice.states["lastDoorbellPressTime"] is None) or
				(indigoDevice.states["lastDoorbellPressTime"] == "")):
			keyValueList.append({'key': 'lastDoorbellPressTime', 'value': stringifiedDistantPast})
		if ((indigoDevice.states["lastMotionTime"] is None) or (indigoDevice.states["lastMotionTime"] == "")):
			keyValueList.append({'key': 'lastMotionTime', 'value': stringifiedDistantPast})

		# Push accumulated state initialization to server, and initialize state image
		indigoDevice.updateStatesOnServer(keyValueList)
		indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.MotionSensor)



	########################################
	# Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
	######################
	def downloadVideoForEvent(self, pluginAction):
		indigoDevice = indigo.devices[pluginAction.deviceId]

		filename = pluginAction.props.get('downloadFilePath', "")
		eventId = ""
		if ("lastEventId" in indigoDevice.states):
			eventId = indigoDevice.states["lastEventId"]
		eventIdOption = pluginAction.props.get('eventIdOption', "lastEventId")
		if eventIdOption == "specifyEventId":
			eventId = pluginAction.props.get('userSpecifiedEventId', "")

		# Make sure we have an event ID to process
		if eventId == "":
			indigo.server.log(u"No Event ID specified to download for %s" % (indigoDevice.name), isError=True)
			return

		if filename:
			ringDevice = self.getExistingRingDeviceMappingForIndigoDevice(indigoDevice.address)

			if (ringDevice.recording_download(eventId, filename, override=True)):
				# Download succeeded
				self.debugLog(u"Downloaded video of event for '%s' to %s" % (indigoDevice.name, filename))

				# Create animated GIF, if requested
				if (pluginAction.props.get('convertToAnimatedGIF', False)):
					self.debugLog("Attempting to convert video to animated GIF")
					gifFilename = filename + ".gif"
					returnCode = subprocess.call("./ffmpeg -i %s -s 600x400 -pix_fmt rgb8 -r 1 -f gif - "
												 "| ./gifsicle --optimize=3 --delay=20 > %s" %
												 (filename, gifFilename), shell=True)
					self.debugLog("Return code from attempting to convert video to animated GIF: %s" % returnCode)
					if (returnCode is not 0):
						indigo.server.log(u"Error converting downloaded video to animated GIF", isError=True)

				# Check for triggers we need to execute
				for triggerId, trigger in sorted(self.activeDownloadCompleteTriggers.iteritems()):
					triggerIndigoDeviceId = trigger.pluginProps.get("indigoDeviceId", "")
					if ((triggerIndigoDeviceId == "-1") or (triggerIndigoDeviceId == str(indigoDevice.id))):
						indigo.trigger.execute(trigger)
			else:
				indigo.server.log(u"Unable to download event id %s for %s" % (eventId, indigoDevice.name), isError=True)
		else:
			indigo.server.log(u"Missing filename setting in action settings for video download of event for '%s'"
							  % indigoDevice.name, isError=True)
			return

		return


	########################################
	# Methods and callbacks defined in Devices.xml:
	####################
	def currentMappedPlusUnmappedRingDevices(self, filter, valuesDict, typeId, targetId):
		# TODO: change to make use of filter to pick device type to iterate over
		self.debugLog(u"Finding currently mapped Ring doorbell device and ones that are not yet mapped "
					  u"to Indigo devices")
		currentMappedPlusUnmappedRingDevicesList = []

		if self.isConnected():
			# Doorbells
			for ringDevice in self.ring.doorbells:
				# Get most up to date data for the Ring device
				ringDevice.update()
				
				# See if there is already a mapping to an Indigo device for this Ring device
				indigoDevice = self.getExistingIndigoDeviceMappingForRingDevice(ringDevice, "doorbell")
				if (indigoDevice is None):
					# Add to the list if no existing mapping
					currentMappedPlusUnmappedRingDevicesList.append((ringDevice.account_id, ringDevice.name))
				elif (("address" in valuesDict) and (str(valuesDict["address"]) == indigoDevice.address)):
					# Add to the list if mapping is to the device we're currently configuring
					currentMappedPlusUnmappedRingDevicesList.append((ringDevice.account_id, ringDevice.name))

		return currentMappedPlusUnmappedRingDevicesList


	########################################
	def ringDoorbellDeviceSelectionChange(self, valuesDict, typeId, devId):
		self.debugLog(u"Ring device selection changed in Indigo device settings")

		mappedRingDevice = self.getExistingRingDeviceMappingForIndigoDevice(valuesDict["doorbellDropDownListSelection"])

		if (mappedRingDevice is not None):
			valuesDict["address"] = mappedRingDevice.account_id
			valuesDict["selectedRingDeviceName"] = mappedRingDevice.name
			valuesDict["selectedRingDeviceId"] = mappedRingDevice.account_id
			valuesDict["selectedRingDeviceLocation"] = mappedRingDevice.address
			valuesDict["selectedRingDeviceModel"] = mappedRingDevice.model
			valuesDict["selectedRingDeviceFamily"] = mappedRingDevice.family
			valuesDict["selectedRingDeviceFirmware"] = mappedRingDevice.firmware
			valuesDict["selectedRingDeviceBatteryLevel"] = mappedRingDevice.battery_life
			valuesDict["selectedRingDeviceVolume"] = mappedRingDevice.volume
			valuesDict["selectedRingDeviceTimezone"] = mappedRingDevice.timezone
			valuesDict["selectedRingDeviceWifiMACAddress"] = mappedRingDevice.id
			valuesDict["selectedRingDeviceWifiNetwork"] = mappedRingDevice.wifi_name
			valuesDict["selectedRingDeviceWifiSignalStrength"] = mappedRingDevice.wifi_signal_strength

		return valuesDict


	########################################
	# Actions defined in Events.xml:
	####################
	def listIndigoDevices(self, filter, valuesDict, typeId, targetId):
		deviceList = [("-1", "Any Ring %s device you have defined in Indigo" % filter)]
		if (filter == ''):
			deviceList = [("-1","Any Ring device you have defined in Indigo")]

		for indigoDevice in indigo.devices.iter("self"):
			if (filter == '') or (indigoDevice.deviceTypeId == filter):
				deviceList.append((indigoDevice.id, indigoDevice.name))
		return deviceList


	########################################
	# Keep track of subscribed triggers
	####################
	def triggerStartProcessing(self, trigger):
		if trigger.pluginTypeId == "doorbellButtonPushedEvent":
			self.activeButtonPushedTriggers[trigger.id] = trigger
		elif trigger.pluginTypeId == "motionDetectedEvent":
			self.activeMotionDetectedTriggers[trigger.id] = trigger
		elif trigger.pluginTypeId == "videoDownloadCompleteEvent":
			self.activeDownloadCompleteTriggers[trigger.id] = trigger


	########################################
	def triggerStopProcessing(self, trigger):
		if trigger.pluginTypeId == "doorbellButtonPushedEvent":
			del self.activeButtonPushedTriggers[trigger.id]
		elif trigger.pluginTypeId == "motionDetectedEvent":
			del self.activeMotionDetectedTriggers[trigger.id]
		elif trigger.pluginTypeId == "videoDownloadCompleteEvent":
			del self.activeDownloadCompleteTriggers[trigger.id]


	########################################
	def getExistingIndigoDeviceMappingForRingDevice(self, ringDevice, indigoDeviceTypeId):
		# TODO: Inefficient to iterate over the indigo devices every time; consider a more efficient mapping
		mappedIndigoDevice = None
		if (indigoDeviceTypeId == "doorbell"):
			for indigoDevice in indigo.devices.iter("self.doorbell"):
				if (indigoDevice.address == str(ringDevice.account_id)):
					mappedIndigoDevice = indigoDevice
					break
		return mappedIndigoDevice


	########################################
	def getExistingRingDeviceMappingForIndigoDevice(self, indigoDeviceAddress):
		# TODO: Inefficient to iterate over the Ring devices every time; consider a more efficient mapping
		mappedRingDevice = None
		for ringDoorbellDevice in self.ring.doorbells:
			if (str(ringDoorbellDevice.account_id) == indigoDeviceAddress):
				mappedRingDevice = ringDoorbellDevice
				break
		return mappedRingDevice


	########################################
	def printRingDeviceToLog(self, ringDevice, logger):
		# TODO: Add in exception checking and uncomment all lines below (also add in capability checking)
		logger(u' ')
		logger(u'Name:          %s' % ringDevice.name)
		logger(u'Account ID:    %s' % ringDevice.account_id)
		# logger(u'Location:      %s' % ringDevice.address)
		logger(u'Model:         %s' % ringDevice.model)
		logger(u'Family:        %s' % ringDevice.family)
		logger(u'Firmware:      %s' % ringDevice.firmware)
		# logger(u'Battery Level: %s' % ringDevice.battery_life)
		logger(u'Volume:        %s' % ringDevice.volume)
		logger(u'Timezone:      %s' % ringDevice.timezone)
		# logger(u'MAC Address:   %s' % ringDevice.id)
		# logger(u'Wifi Name:     %s' % ringDevice.wifi_name)
		# logger(u'Wifi RSSI:     %s' % ringDevice.wifi_signal_strength)