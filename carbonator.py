# -- coding: utf-8 --
# Created by Blake Cornell, CTO, Integris Security LLC
# Modified by Ik4ru5
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
	
		print "Initiating Carbonator against: %s" % str(self.url)
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
		
		print "New issue identified: Issue # %i " % len(self.scanner_results);
		
		return


	def generateReport(self):		
		print "Generating report ... "
		fileNameXML = self.reportPath + self.reportName + '.' + self.reportFormat.lower()
		fileNameHTML = self.reportPath + self.reportName + '.html'
		print "Saving to %s" % fileNameXML
		self._callbacks.generateScanReport(self.reportFormat.upper(), self.scanner_results, File(fileNameXML))
		self._callbacks.generateScanReport("HTML", self.scanner_results, File(fileNameHTML))
		
		print "Report generated. File is located at %s" % (fileNameXML)
		
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
			
			if int(cli[2]) > 0 and int(cli[2]) <= 65535:
				self.port = int(cli[2])
			else:
				self.port = 80
				
			if len(cli) > 3:
				self.path = cli[3]
			else:
				self.path = '/'
				
			if len(cli) > 4:
				if str(cli[4]).endswith('/'):
					self.reportPath = cli[4]
				else:
					self.reportPath = cli[4] + '/'
			else:
				self.reportPath = './'
				
			
			if len(cli) > 5:
				if cli[5].upper() != 'XML' and cli[5].upper() != 'HTML':
					print "Unkown format for report: %s" % cli[5]
					return False
				else:
					self.reportFormat = cli[5]
			else:
				self.reportFormat = 'XML'
			
			if len(cli) > 6:
				self.reportName = cli[6]
			else:
				self.reportName = self.scheme + '_' + self.fqdn + '_' + str(self.port)
				
			if len(cli) > 8:
				print "Unknown number of CLI arguments"
				self.printUsage()
				
				return False
			
			self.url = URL(self.scheme, self.fqdn, self.port, self.path)
		else:
			print "Invalid command line arguments supplied"
			return False
		return True
