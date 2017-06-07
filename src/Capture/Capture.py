#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import time
import sys
import os  
import threading
from Rule.Rules import *
from File.Files import *
from scapy.all import * 

class ICapture:
	__metaclass__ = ABCMeta 

	@abstractmethod 
	def initFilter(cls):
		pass

	@abstractmethod 
	def readyCaptureNotify(cls):
		pass

	@abstractmethod 
	def startCapture(cls):
		pass

	@abstractmethod 
	def stopCapture(cls):
		pass

class Capture(ICapture): 
	__timer = None
	__forceWTimeOut = 15 
	__preCount = 0 
	__capFiter = ''
	__maxWLine = 100
	__pkts = []
	__count = 0 
	__stop = 0  
	__filecls = None
	__curDstIp = ''
	__curDstPort = ''
	__curSourceIp = ''
	__curSourcePort = ''
	__curMaxLine = ''
	__rule = None  
 
	@classmethod 
	def __init__(cls):
		cls.initFilter()
		cls.__filecls = PcapFile()

	@classmethod 
	def getCurCapFiter(cls):
		return cls.__capFiter

	@classmethod 
	def getCurDstIp(cls):
		return cls.__curDstIp

	@classmethod 
	def getCurDstPort(cls):
		return cls.__curDstPort
		
	@classmethod 
	def getCurSourceIp(cls):
		return cls.__curSourceIp
		
	@classmethod 
	def getCurSourcePort(cls):
		return cls.__curSourcePort

	@classmethod 
	def initFilter(cls):
		cls.__rule = PcapRules.GetInstance()
		cls.__curDstIp = cls.__rule.getCaptureDstIp()
		cls.__capFiter = "tcp and dst net " + cls.__curDstIp
		cls.__dstip = cls.__rule.getCaptureDstIp()
		if len(cls.__rule.getCaptureDstPort()) > 0:
			cls.__curDstPort = cls.__rule.getCaptureDstPort()
			cls.__capFiter += " and dst port " + cls.__curDstPort
		if len(cls.__rule.getCaptureSourceIp()) > 0:
			cls.__curSourceIp = cls.__rule.getCaptureSourceIp()
			cls.__capFiter += " and src host " + cls.__curSourceIp
		if len(cls.__rule.getCaptureSourcePort()) > 0:
			cls.__curSourcePort = cls.__rule.getCaptureSourcePort()
			cls.__capFiter += " and src port " + cls.__curSourcePort

		if cls.__rule.getSaveMaxLine() > 0:
			cls.__curMaxLine = cls.__rule.getSaveMaxLine()

	@classmethod 
	def __idleLongTime(cls):
		if cls.__preCount == cls.__count and cls.__count > 0 and len(cls.__pkts) > 0:
			cls.__filecls.saveDataToFile(cls.__pkts)
			cls.__pkts = []  
			cls.__count = 0
			cls.__preCount = 0

	@classmethod 
	def readyCaptureNotify(cls,x):
		cls.__pkts.append(x)  
		cls.__count += 1  
		if int(cls.__count) == int(cls.__curMaxLine):  
			cls.__filecls.saveDataToFile(cls.__pkts)
			cls.__pkts = []  
			cls.__count = 0 
			cls.__preCount = 0
		else:
			if cls.__timer != None:
				cls.__timer.cancel()
			cls.__preCount = cls.__count
			cls.__timer = threading.Timer(cls.__forceWTimeOut, cls.__idleLongTime)
			cls.__timer.start()

	@classmethod 
	def startCapture(cls):
		cls.__stop = 0 
		print "Begin Capture: " + cls.__capFiter + "..."
		sniff(filter=cls.__capFiter, prn=cls.readyCaptureNotify, stop_filter=cls.isStop) 

	@classmethod 
	def stopCapture(cls):
		cls.__stop = 1 
		print "Stop Capture: " + cls.__capFiter + " success!"
		if cls.__timer != None:
			cls.__timer.cancel() 

	@classmethod 
	def isStop(cls, x):
		return cls.__stop

def UnitTest():
	th = Capture()

if __name__=='__main__': 
	UnitTest()
