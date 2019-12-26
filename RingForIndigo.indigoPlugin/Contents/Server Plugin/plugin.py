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
		self.utc = pytz.UTC
		# TODO: Initialize some lookup tables mapping Indigo devices to Ring devices?


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
					self.makeConnectionToRing(self.pluginPrefs['Username'], self.pluginPrefs['Password'])

				# If we are connected, update events and device status (otherwise, wait until after sleep to try again)
				if (self.isConnected() is True):
					self.debugLog(u"Getting updates from Ring.com API")

					# Doorbells
					for ringDevice in self.ring.doorbells:
						# Check to see if this ringDevice is mapped to an Indigo device
						indigoDevice = self.getExistingIndigoDeviceMapping(ringDevice, "doorbell")
						if (indigoDevice is not None):
							# Get latest state and events for Ring device
							ringDevice.update()
							# TODO is there any reason to worry about the stale data in pluginProps?  Just gets updated when device list built
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
							indigoDevice.updateStateOnServer("ringDeviceWifiSignalStrength", ringDevice.wifi_signal_strength)
							# self.debugLog(u"%s" % indigoDevice)

							for event in ringDevice.history(limit=30):
								indigoDeviceLastEventTime = self.utc.localize(datetime.datetime.strptime(indigoDevice.states["lastEventTime"], '%Y-%m-%d %H:%M:%S %Z'))
								ringDeviceEventTime = event["created_at"]
								isNewEvent =  indigoDeviceLastEventTime < ringDeviceEventTime
								if isNewEvent:
									self.debugLog("Processing an event for %s" % indigoDevice.name)
									# try:
									# 	self.updateStateOnServer(dev, "lastEventId", str(event.id))
									# except:
									# 	self.de(dev, "lastEventId")
									# try:
									# 	self.updateStateOnServer(dev, "lastEvent", event.kind)
									# except:
									# 	self.de(dev, "lastEvent")
									# try:
									# 	self.updateStateOnServer(dev, "lastEventTime", str(event.now))
									# except:
									# 	self.de(dev, "lastEventTime")
									# try:
									# 	self.updateStateOnServer(dev, "lastAnswered", event.answered)
									# except:
									# 	self.de(dev, "lastAnswered")
									#
									# if (event.kind == "motion"):
									# 	try:
									# 		self.updateStateOnServer(dev, "lastMotionTime", str(event.now))
									# 	except:
									# 		self.de(dev, "lastMotionTime")
									# else:
									# 	try:
									# 		self.updateStateOnServer(dev, "lastButtonPressTime", str(event.now))
									# 	except:
									# 		self.de(dev, "lastButtonPressTime")

				# TODO Change to use a user specified update frequency
				self.sleep(20) # in seconds
		except self.StopThread:
			# Close connection to Ring API
			self.closeConnectionToRing()
			pass


	########################################
	# Actions defined in MenuItems.xml:
	####################
	# def refreshAvailableRingDevices(self):
	# 	return


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

		# Update connection to Ring API based on changes to credentials
		self.makeConnectionToRing(valuesDict.get("Username", None), valuesDict.get("Password", None))

		# PluginPrefs will be updated AFTER we exit this method if we say validation was good
		self.debugLog(u"Validated plugin configuration changes")
		return True


	########################################
	def deviceStartComm(self, indigoDevice):
		# Called when communication with the hardware should be started.
		# Initialize device state
		indigoDevice.updateStateOnServer("ringDeviceId", indigoDevice.address)

		# TODO - data in pluginProps is stale - its from when device was configged, not up to date
		# Instead, should probably be using latest data from Ring API...  only thing that should
		indigoDevice.updateStateOnServer("ringDeviceName", indigoDevice.pluginProps.get("selectedRingDeviceName", ""))
		indigoDevice.updateStateOnServer("ringDeviceLocation", indigoDevice.pluginProps.get("selectedRingDeviceLocation", ""))
		indigoDevice.updateStateOnServer("ringDeviceModel", indigoDevice.pluginProps.get("selectedRingDeviceModel", ""))
		indigoDevice.updateStateOnServer("ringDeviceFamily", indigoDevice.pluginProps.get("selectedRingDeviceFamily", ""))
		indigoDevice.updateStateOnServer("ringDeviceFirmware", indigoDevice.pluginProps.get("selectedRingDeviceFirmware", ""))
		indigoDevice.updateStateOnServer("ringDeviceBatteryLevel", indigoDevice.pluginProps.get("selectedRingDeviceBatteryLevel", ""))
		indigoDevice.updateStateOnServer("ringDeviceVolume", indigoDevice.pluginProps.get("selectedRingDeviceVolume", ""))
		indigoDevice.updateStateOnServer("ringDeviceTimezone", indigoDevice.pluginProps.get("selectedRingDeviceTimezone", ""))
		indigoDevice.updateStateOnServer("ringDeviceWifiMACAddress", indigoDevice.pluginProps.get("selectedRingDeviceWifiMACAddress", ""))
		indigoDevice.updateStateOnServer("ringDeviceWifiNetwork", indigoDevice.pluginProps.get("selectedRingDeviceWifiNetwork", ""))
		indigoDevice.updateStateOnServer("ringDeviceWifiSignalStrength", indigoDevice.pluginProps.get("selectedRingDeviceWifiSignalStrength", ""))

		# Initialize lastEventTime to date in distant past
		distantPast = datetime.datetime(
			year=1900,
			month=01,
			day=01,
			hour=0,
			minute=0,
			second=0,
			tzinfo=pytz.UTC)
		indigoDevice.updateStateOnServer("lastEventTime", datetime.datetime.strftime(distantPast, '%Y-%m-%d %H:%M:%S %Z'))

	########################################
	# Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
	######################
	# def downloadVideo(self, pluginAction):
	# 	self.debugLog(u"downloadVideo action called:\n" + str(pluginAction))
	# 	return


	########################################
	# Methods and callbacks defined in Devices.xml:
	####################
	def currentMappingAndUnmappedRingDevices(self, filter, valuesDict, typeId, targetId):
		# TODO: change to make use of filter to pick device type to iterate over
		self.debugLog(u"Finding Ring doorbell devices that are not yet mapped to Indigo devices")
		currentAndUnmappedRingDevices = []

		if self.isConnected():
			for ringDevice in self.ring.doorbells:
				# Get most up to date data for the Ring device
				ringDevice.update()
				
				# See if there is already a mapping to an Indigo device for this Ring device
				indigoDevice = self.getExistingIndigoDeviceMapping(ringDevice, "doorbell")
				if ((indigoDevice is None) or (str(valuesDict["address"]) == indigoDevice.address)):
					# Add to the list if no existing mapping, or if mapping is to the device we're currently configuring
					currentAndUnmappedRingDevices.append((ringDevice.account_id, ringDevice.name))

		return currentAndUnmappedRingDevices


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
	def debugPrintRingDevice(self, ringDevice):
		self.debugLog(u' ')
		self.debugLog(u'Name:       %s' % ringDevice.name)
		self.debugLog(u'Account ID: %s' % ringDevice.account_id)
		self.debugLog(u'Address:    %s' % ringDevice.address)
		self.debugLog(u'Family:     %s' % ringDevice.family)
		self.debugLog(u'ID:         %s' % ringDevice.id)
		self.debugLog(u'Timezone:   %s' % ringDevice.timezone)
		self.debugLog(u'Wifi Name:  %s' % ringDevice.wifi_name)
		self.debugLog(u'Wifi RSSI:  %s' % ringDevice.wifi_signal_strength)