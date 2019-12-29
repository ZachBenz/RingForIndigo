#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2019, Zach Benz, All rights reserved.
# https://github.com/ZachBenz/RingForIndigo

import indigo

import os
import sys
import time
import requests
import datetime
import pytz
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
		self.dateFormatString = '%Y-%m-%d %H:%M:%S %Z'
		# TODO: Initialize some tables mapping Indigo devices to Ring devices to make things lookups more efficient?


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
						indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)

					# Doorbells
					for ringDevice in self.ring.doorbells:
						# Check to see if this ringDevice is mapped to an Indigo device
						indigoDevice = self.getExistingIndigoDeviceMapping(ringDevice, "doorbell")
						if (indigoDevice is not None):
							# Get latest state and events for Ring device
							ringDevice.update()
							# TODO: use a keyValueList to update states in one fell swoop, instead of one at a time
							#  - see SDK sensor plugin example
							indigoDevice.updateStateOnServer("ringDeviceName", ringDevice.name)
							indigoDevice.updateStateOnServer("ringDeviceId", ringDevice.account_id)
							indigoDevice.updateStateOnServer("ringDeviceLocation", ringDevice.address)
							indigoDevice.updateStateOnServer("ringDeviceModel", ringDevice.model)
							indigoDevice.updateStateOnServer("ringDeviceFamily", ringDevice.family)
							indigoDevice.updateStateOnServer("ringDeviceFirmware", ringDevice.firmware)
							indigoDevice.updateStateOnServer("ringDeviceBatteryLevel", ringDevice.battery_life)
							indigoDevice.updateStateOnServer("ringDeviceVolume", ringDevice.volume)
							indigoDevice.updateStateOnServer("ringDeviceTimezone", ringDevice.timezone)
							indigoDevice.updateStateOnServer("ringDeviceWifiMACAddress", ringDevice.id)
							indigoDevice.updateStateOnServer("ringDeviceWifiNetwork", ringDevice.wifi_name)
							indigoDevice.updateStateOnServer("ringDeviceWifiSignalStrength",
															 ringDevice.wifi_signal_strength)

							indigoDeviceLastEventTime = datetime.datetime.strptime(
								indigoDevice.states["lastEventTime"], self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDeviceLastDoorbellPressTime = datetime.datetime.strptime(
								indigoDevice.states["lastDoorbellPressTime"], self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDeviceLastMotionTime = datetime.datetime.strptime(
								indigoDevice.states["lastMotionTime"], self.dateFormatString).replace(tzinfo=pytz.UTC)
							indigoDevicePreviousMostRecentEvent = indigoDeviceLastEventTime

							# TODO: Make history limit a heuristic, multiplicative factor of update (sleep) frequency
							for event in ringDevice.history(limit=10):
								ringDeviceEventTime = \
									event["created_at"].astimezone(pytz.utc)
								isNewEventToProcess =  indigoDevicePreviousMostRecentEvent < ringDeviceEventTime
								if isNewEventToProcess:
									self.debugLog("Processing a new event for %s: %s, answered: %s" %
												  (indigoDevice.name, event["kind"], event["answered"]))
									stringifiedTime = datetime.datetime.strftime(ringDeviceEventTime,
																				 self.dateFormatString)

									if (indigoDeviceLastEventTime < ringDeviceEventTime):
										indigoDeviceLastEventTime = ringDeviceEventTime
										indigoDevice.updateStateOnServer("lastEventTime", stringifiedTime)
										indigoDevice.updateStateOnServer("lastEventId", event["id"])
										indigoDevice.updateStateOnServer("lastEventKind", event["kind"])
										indigoDevice.updateStateOnServer("wasLastEventAnswered", event["answered"])

									if (event["kind"] == 'motion'):
										if (indigoDeviceLastMotionTime < ringDeviceEventTime):
											indigoDeviceLastMotionTime = ringDeviceEventTime
											indigoDevice.updateStateOnServer("lastMotionTime", stringifiedTime)
											indigoDevice.updateStateOnServer("onOffState", True)
											indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.SensorTripped)

									elif (event["kind"] == 'ding'):
										if (indigoDeviceLastDoorbellPressTime < ringDeviceEventTime):
											indigoDeviceLastDoorbellPressTime = ringDeviceEventTime
											indigoDevice.updateStateOnServer("lastDoorbellPressTime", stringifiedTime)

									# TODO: track on_demand event type?

				# TODO Change to use a user specified update frequency
				self.sleep(10) # in seconds
		except self.StopThread:
			# Close connection to Ring API
			self.closeConnectionToRing()
			pass


	########################################
	# Actions defined in MenuItems.xml:
	####################
	# def refreshAvailableRingDevices(self):
	# 	return


	########################################
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


	# ########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		if (valuesDict["doorbellDropDownListSelection"] == ""):
			errorDict = indigo.Dict()
			errorDict["doorbellDropDownListSelection"] = "You must pick an available Ring device from the dropdown list"
			return(False, valuesDict, errorDict)
		return True


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


	########################################
	def deviceStartComm(self, indigoDevice):
		# Called when communication with the hardware should be started.

		# Initialize onOffState and state image
		indigoDevice.updateStateOnServer("onOffState", False)
		indigoDevice.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)

		# Initialize device state for newly created Indigo devices
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
			indigoDevice.updateStateOnServer("lastEventTime", stringifiedDistantPast)
		if ((indigoDevice.states["lastDoorbellPressTime"] is None) or (indigoDevice.states["lastDoorbellPressTime"] == "")):
			indigoDevice.updateStateOnServer("lastDoorbellPressTime", stringifiedDistantPast)
		if ((indigoDevice.states["lastMotionTime"] is None) or (indigoDevice.states["lastMotionTime"] == "")):
			indigoDevice.updateStateOnServer("lastMotionTime", stringifiedDistantPast)


	########################################
	# Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
	######################
	# def downloadVideo(self, pluginAction):
	# 	self.debugLog(u"downloadVideo action called:\n" + str(pluginAction))
	# 	return


	########################################
	# Methods and callbacks defined in Devices.xml:
	####################
	def currentMappedPlusUnmappedRingDevices(self, filter, valuesDict, typeId, targetId):
		# TODO: change to make use of filter to pick device type to iterate over
		self.debugLog(u"Finding currently mapped Ring doorbell device and ones that are not yet mapped to Indigo devices")
		currentMappedPlusUnmappedRingDevicesList = []

		if self.isConnected():
			# Doorbells
			for ringDevice in self.ring.doorbells:
				# Get most up to date data for the Ring device
				ringDevice.update()
				
				# See if there is already a mapping to an Indigo device for this Ring device
				indigoDevice = self.getExistingIndigoDeviceMapping(ringDevice, "doorbell")
				if ((indigoDevice is None) or (str(valuesDict["address"]) == indigoDevice.address)):
					# Add to the list if no existing mapping, or if mapping is to the device we're
					# currently configuring
					currentMappedPlusUnmappedRingDevicesList.append((ringDevice.account_id, ringDevice.name))

		return currentMappedPlusUnmappedRingDevicesList


	########################################
	def ringDoorbellDeviceSelectionChange(self, valuesDict, typeId, devId):
		self.debugLog(u"Ring device selection changed in Indigo device settings")

		# TODO: Inefficient to iterate over the Ring devices every time; consider a more efficient mapping
		mappedRingDevice = None
		for ringDoorbellDevice in self.ring.doorbells:
			if (str(ringDoorbellDevice.account_id) == valuesDict["doorbellDropDownListSelection"]):
				mappedRingDevice = ringDoorbellDevice
				break

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
	def getExistingIndigoDeviceMapping(self, ringDevice, indigoDeviceTypeId):
		# TODO: Inefficient to iterate over the indigo devices every time; consider a more efficient mapping
		mappedIndigoDevice = None
		if (indigoDeviceTypeId == "doorbell"):
			for indigoDevice in indigo.devices.iter("self.doorbell"):
				if (indigoDevice.address == str(ringDevice.account_id)):
					mappedIndigoDevice = indigoDevice
					break
		return mappedIndigoDevice


	########################################
	def printRingDeviceToLog(self, ringDevice, logger):
		# TODO: uncomment all lines below
		logger(u' ')
		logger(u'Name:          %s' % ringDevice.name)
		logger(u'Account ID:    %s' % ringDevice.account_id)
		# logger(u'Location:      %s' % ringDevice.address)
		logger(u'Model:         %s' % ringDevice.model)
		logger(u'Family:        %s' % ringDevice.family)
		logger(u'Firmware:      %s' % ringDevice.firmware)
		logger(u'Battery Level: %s' % ringDevice.battery_life)
		logger(u'Volume:        %s' % ringDevice.volume)
		logger(u'Timezone:      %s' % ringDevice.timezone)
		# logger(u'MAC Address:   %s' % ringDevice.id)
		# logger(u'Wifi Name:     %s' % ringDevice.wifi_name)
		# logger(u'Wifi RSSI:     %s' % ringDevice.wifi_signal_strength)