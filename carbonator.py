# -- coding: utf-8 --
# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v1.2
# Released under GPL Version 2 license.
#
# See the INSTALL file for installation instructions.
# 
# For more information contact us at carbonator at integrissecurity dot com
# Or visit us at https://www.integrissecurity.com/
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File

import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._callbacks.setExtensionName("Carbonator")
		self.clivars = None

		self.spider_results = []
		self.scanner_results = []
		self.packet_timeout = 5

		self.last_packet_seen = int(time.time()) #initialize the start of the spider/scan

		if not self.processCLI():
			return None
		else:
			self.clivars = True
	
		print "Initiating Carbonator against: %s", str(self.url)
		#add to scope if not already in there.
		if self._callbacks.isInScope(self.url) == 0:
			self._callbacks.includeInScope(self.url)
	
		#added to ensure that the root directory is scanned
		base_request = str.encode(str("GET %s HTTP/1.1\nHost: %s\n\n" % (self.path, self.fqdn)))
		if(self.scheme == 'HTTPS'):
			print self._callbacks.doActiveScan(self.fqdn, self.port, 1, base_request)
		else:
			print self._callbacks.doActiveScan(self.fqdn, self.port, 0, base_request)
	
		self._callbacks.sendToSpider(self.url)
		self._callbacks.registerHttpListener(self)
		self._callbacks.registerScannerListener(self)
	
		while int(time.time()) - self.last_packet_seen <= self.packet_timeout:
			time.sleep(1)
		
		print "No packets seen in the last %i seconds." % self.packet_timeout
		print "Removing listeners"
		
		self._callbacks.removeHttpListener(self)
		self._callbacks.removeScannerListener(self)
		self._callbacks.excludeFromScope(self.url)
	
		self.generateReport()
		
		print "Closing Burp Suite in %i seconds." % self.packet_timeout
		time.sleep(self.packet_timeout)
	
		if self.clivars:
			self._callbacks.exitSuite(False)
			
		return


	def processHttpMessage(self, tool_flag, isRequest, current):
		self.last_packet_seen = int(time.time())
		
		if tool_flag == self._callbacks.TOOL_SPIDER and isRequest: #if is a spider request then send to scanner
			self.spider_results.append(current)
			print "Sending new URL to Vulnerability Scanner: URL # %i" % len(self.spider_results)
			if self.scheme == 'https':
				self._callbacks.doActiveScan(self.fqdn, self.port, 1, current.getRequest()) #returns scan queue, push to array
			else:
				self._callbacks.doActiveScan(self.fqdn, self.port, 0, current.getRequest()) #returns scan queue, push to array
				
		return


	def newScanIssue(self, issue):
		self.scanner_results.append(issue)
		
		print "New issue identified: Issue # %i " %len(self.scanner_results);
		
		return


	def generateReport(self):		
		print "Generating report ... "
		fileName = self.reportPath + self.scheme + '_' + self.fqdn + '_' + str(self.port) + '.' + format.lower()
		self._callbacks.generateScanReport(format.upper(), self.scanner_results, File(fileName))
		
		print "Report generated. File is located at %s" % (fileName)
		
		return


	def printInfo(self):
		print "Integris Security Carbonator is now loaded."
		print "If Carbonator was loaded through the BApp store then you can run in headless mode simply adding the `-Djava.awt.headless=true` flag from within your shell. Note: If burp doesn't close at the conclusion of a scan then disable Automatic Backup on Exit."
		print "For questions or feature requests contact us at carbonator at integris security dot com."
		print "Visit carbonator at https://www.integrissecurity.com/Carbonator"


	def printUsage(self):
		print "java -jar path/to/burp.jar scheme fqdn port [path [reportFormat [reportPath]]"
		print "for example: java -jar path/to/burp.jar http example.com 80 / XML"


	def processCLI(self):
		cli = self._callbacks.getCommandLineArguments()
		
		if len(cli) < 0:
			print "Incomplete target information provided."
			
			return False
		elif not cli:
			self.printInfo();
				
			return False
			
		elif cli[0] == 'https' or cli[0] == 'http': #cli[0]=scheme,cli[1]=fqdn,cli[2]=port
			self.scheme = cli[0]
			self.fqdn = cli[1]
			
			if cli[2] > 0 and cli[2] <= 65535:
				self.port = int(cli[2])
			else:
				self.port = 80
				
			if cli[3]:
				self.path = cli[3]
			else:
				self.path = '/'
				
			if cli[4]:
				if cli[4].upper() != 'XML' and cli[4].upper() != 'HTML':
					print "Unkown format for report: %s" % cli[4]
					return False
				else:
					self.reportFormat = cli[4]
			else:
				self.reportFormat = 'XML'
				
			if cli[5]:
				if str(cli[5]).endswith('/'):
					self.reportPath = cli[5]
				else:
					self.reportPath = cli[5] + '/'
			else:
				self.reportPath = './'
				
			if len(cli) > 6:
				print "Unknown number of CLI arguments"
				self.printUsage()
				
				return False
			
			self.url = URL(self.scheme, self.fqdn, self.port, self.path)
		else:
			print "Invalid command line arguments supplied"
			return False
		return True
