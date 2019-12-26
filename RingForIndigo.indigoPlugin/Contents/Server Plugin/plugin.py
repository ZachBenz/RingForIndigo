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
		# TODO: Initialize some lookup tables by Indigo device id?

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

					# Update device mappings
					for ringDevice in list(self.ring.stickup_cams + self.ring.chimes + self.ring.doorbells):
						ringDevice.update()
						# TODO add in actual device and event updating...
						# TODO update both pluginProps (for device settings) and state (current), as appropriate
						# self.debugLog(u' ')
						# self.debugLog(u'Name:       %s' % ringDevice.name)
						# self.debugLog(u'Account ID: %s' % ringDevice.account_id)
						# self.debugLog(u'Address:    %s' % ringDevice.address)
						# self.debugLog(u'Family:     %s' % ringDevice.family)
						# self.debugLog(u'ID:         %s' % ringDevice.id)
						# self.debugLog(u'Timezone:   %s' % ringDevice.timezone)
						# self.debugLog(u'Wifi Name:  %s' % ringDevice.wifi_name)
						# self.debugLog(u'Wifi RSSI:  %s' % ringDevice.wifi_signal_strength)

				# TODO Change to use a user specified update frequency
				self.sleep(120) # in seconds
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
		return (True, valuesDict)

	########################################
	def validatePrefsConfigUi(self, valuesDict):
		# Update debug log print setting
		self.debug = valuesDict.get(u"printDebugInEventLog", False)

		# Update connection to Ring API based on changes to credentials
		self.makeConnectionToRing(valuesDict.get("Username", None), valuesDict.get("Password", None))

		# PluginPrefs will be updated AFTER we exit this method if we say validation was good
		self.debugLog(u"Validated plugin configuration changes")
		return (True, valuesDict)

	########################################
	def deviceStartComm(self, dev):
		# Called when communication with the hardware should be started.
		# Initialize device state
		dev.updateStateOnServer("ringDeviceId", dev.address)

		# TODO - data in pluginProps is stale - its from when device was configged, not up to date
		# Instead, should probably be using latest data from Ring API...  only thing that should
		dev.updateStateOnServer("ringDeviceName", dev.pluginProps.get("selectedRingDeviceName", ""))
		dev.updateStateOnServer("ringDeviceLocation", dev.pluginProps.get("selectedRingDeviceLocation", ""))
		dev.updateStateOnServer("ringDeviceModel", dev.pluginProps.get("selectedRingDeviceModel", ""))
		dev.updateStateOnServer("ringDeviceFamily", dev.pluginProps.get("selectedRingDeviceFamily", ""))
		dev.updateStateOnServer("ringDeviceFirmware", dev.pluginProps.get("selectedRingDeviceFirmware", ""))
		dev.updateStateOnServer("ringDeviceBatteryLevel", dev.pluginProps.get("selectedRingDeviceBatteryLevel", ""))
		dev.updateStateOnServer("ringDeviceVolume", dev.pluginProps.get("selectedRingDeviceVolume", ""))
		dev.updateStateOnServer("ringDeviceTimezone", dev.pluginProps.get("selectedRingDeviceTimezone", ""))
		dev.updateStateOnServer("ringDeviceWifiMACAddress", dev.pluginProps.get("selectedRingDeviceWifiMACAddress", ""))
		dev.updateStateOnServer("ringDeviceWifiNetwork", dev.pluginProps.get("selectedRingDeviceWifiNetwork", ""))
		dev.updateStateOnServer("ringDeviceWifiSignalStrength", dev.pluginProps.get("selectedRingDeviceWifiSignalStrength", ""))

		self.debugLog(u"Device:\n%s" % dev)

	########################################
	# Plugin Actions object callbacks (pluginAction is an Indigo plugin action instance)
	######################
	# def downloadVideo(self, pluginAction):
	# 	self.debugLog(u"downloadVideo action called:\n" + str(pluginAction))
	# 	return

	########################################
	# Methods and callbacks defined in Devices.xml:
	####################
	def unmappedRingDoorbellDevices(self, filter, valuesDict, typeId, targetId):
		self.debugLog(u"Finding Ring doorbell devices that are not yet mapped to Indigo devices")
		unmappedRingDoorbellDevices = []

		if self.isConnected():
			for ringDoorbellDevice in self.ring.doorbells:
				self.debugLog(u"Name: %s" % ringDoorbellDevice.name)
				# See if there is already a mapping for this doorbell

				# TODO: Inefficient to iterate over the indigo devices every time; consider a more efficient mapping
				foundMappedDevice = False
				for indigoDevice in indigo.devices.iter("self.doorbell"):
					if (indigoDevice.states["ringDeviceId"] == str(ringDoorbellDevice.account_id)):
						foundMappedDevice = True
						break

				if (foundMappedDevice is False):
					unmappedRingDoorbellDevices.append((ringDoorbellDevice.account_id, ringDoorbellDevice.name))

		return unmappedRingDoorbellDevices

	########################################
	def ringDoorbellDeviceSelectionChange(self, valuesDict, typeId, devId):
		self.debugLog(u"Ring device selection changed in Indigo device settings")

		# TODO: Inefficient to iterate over the Ring devices every time; consider a more efficient mapping
		mappedRingDevice = None
		for ringDoorbellDevice in self.ring.doorbells:
			if (str(ringDoorbellDevice.account_id) == valuesDict["selectedRingDoorbellDevice"]):
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
	# def updateRingDoorbellDeviceMapping(self, valuesDict, typeId, devId):
	# 	self.debugLog(u"Updating mapping from Ring doorbell device to Indigo device")
	# 	return