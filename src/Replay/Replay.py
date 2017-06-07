#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import time
import sys
import os 
from Rule.Rules import *
from File.Files import *
from PktsParser import *

class IReplay:
	__metaclass__ = ABCMeta 

	@abstractmethod 
	def initFilter(cls):
		pass

	@abstractmethod 
	def startReplay(cls):
		pass

	@abstractmethod 
	def stopReplay(cls):
		pass

class Replay(IReplay): 
	dir = ''
	__stop = 0  
	__onePkgTargetIp = ''
	__onePkgTargetPort = ''
	__onePkgTimeStamp = 0
	__curTargetIp = ''
	__curTargetPort = ''
	__curOriSourceIp = ''
	__curOriSourcePort = ''
	__curStartTime = 0
	__curEndTime = 0
	__repFiles = []
	__rule = None
	__filecls = None
	__pktsparser = None
 
	@classmethod 
	def __init__(cls):
		cls.initFilter()
		cls.__filecls = PcapFile()
		cls.__pktsparser = PktsParser()

	@classmethod 
	def getCurTargetIp(cls):
		return cls.__curTargetIp

	@classmethod 
	def getCurTargetPort(cls):
		return cls.__curTargetPort
		
	@classmethod 
	def getCurOriSourceIp(cls):
		return cls.__curOriSourceIp
		
	@classmethod 
	def getCurOriSourcePort(cls):
		return cls.__curOriSourcePort

	@classmethod 
	def getCurStartTime(cls):
		return cls.__curStartTime

	@classmethod 
	def getCurEndTime(cls):
		return cls.__curEndTime

	@classmethod 
	def __convertUnixTimestamp(cls, tm):
		listTime = tm.split("T") 
		ymd = listTime[0].split("-") 
		hms = listTime[1].split(":") 
		t = (int(ymd[0]), int(ymd[1]), int(ymd[2]), int(hms[0]), int(hms[1]), int(hms[2]), 0, 0, 0)
		secs = time.mktime(t)
		return int(secs)

	@classmethod 
	def __isCapFileExist(cls):
		ret = True
		if False == os.path.exists(cls.dir):
			print "target replay ip packages not exist!"
			ret = False

		cls.__repFiles = []
		cls.__filecls.getDirFiles(cls.dir, cls.__repFiles)
		if len(cls.__repFiles) <= 0:
			print "target replay ip packages not exist!"
			ret = False
		return ret

	@classmethod 
	def initFilter(cls):
		cls.__rule = PcapRules.GetInstance()
		cls.__curTargetIp = cls.__rule.getReplayTargetIp()
		cls.__curTargetPort = cls.__rule.getReplayTargetPort()
		if len(cls.__rule.getReplayStarttime()) > 0:
			cls.__curStartTime = cls.__convertUnixTimestamp(cls.__rule.getReplayStarttime())
		if len(cls.__rule.getReplayEndtime()) > 0:
			cls.__curEndTime = cls.__convertUnixTimestamp(cls.__rule.getReplayEndtime())
		cls.dir = '../file/' 
		cls.dir += cls.__curTargetIp + "/"

	@classmethod 
	def __parseFilePath(cls, fpath):
		cls.__onePkgTargetIp = ''
		cls.__onePkgTargetPort = ''
		arrs =  fpath.split('/')
		if len(arrs) > 3:
			cls.__onePkgTargetIp = arrs[2]
		if len(arrs) > 4:
			cls.__onePkgTargetPort = arrs[3]
		
		cls.__onePkgTimeStamp = arrs[len(arrs)-1].split('.')[0]

	@classmethod 
	def __canReplay(cls):
		if int(cls.__curStartTime) > 0 and int(cls.__curEndTime) > 0 and (int(cls.__onePkgTimeStamp) < int(cls.__curStartTime) or int(cls.__onePkgTimeStamp) > int(cls.__curEndTime)):
			return False
 
		if False == (cls.__onePkgTargetIp == cls.__curTargetIp and (cls.__onePkgTargetPort == cls.__curTargetPort or len(cls.__onePkgTargetPort) <= 0)):
			return False

		return True

	@classmethod 
	def __replayOneCapFile(cls, fpath):
		if cls.__canReplay() == True:
			cls.__pktsparser.parseCapStream(fpath)

	@classmethod 
	def __replayCapFiles(cls):
		for idx, val in enumerate(cls.__repFiles):
			
			if cls.__stop == 1:
				return

			cls.__parseFilePath(val)
			cls.__replayOneCapFile(val)

	@classmethod 
	def startReplay(cls):
		if cls.__isCapFileExist() == False:
			return

		cls.__stop = 0 
		print "Begin Replay... : target ip " + cls.__curTargetIp + " port " + cls.__curTargetPort
		cls.__replayCapFiles()

	@classmethod 
	def stopReplay(cls):
		cls.__stop = 1  
		print "Stop Replay! : target ip " + cls.__curTargetIp + " port " + cls.__curTargetPort

def UnitTest():
	th = Replay()

if __name__=='__main__': 
	UnitTest()
