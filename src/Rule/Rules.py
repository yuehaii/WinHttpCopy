#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import threading

class IRules:
	__metaclass__ = ABCMeta 

	@abstractmethod 
	def setAction(cls, act):
		pass
	@abstractmethod 
	def getAction(cls):
		pass
	@abstractmethod 
	def setCaptureSourceIp(cls, ip):
		pass
	@abstractmethod 
	def getCaptureSourceIp(cls):
		pass
	@abstractmethod 
	def setCaptureSourceHost(cls, host):
		pass
	@abstractmethod 
	def getCaptureSourceHost(cls):
		pass
	@abstractmethod 
	def setCaptureSourcePort(cls, port):
		pass
	@abstractmethod 
	def getCaptureSourcePort(cls):
		pass
	@abstractmethod 
	def setCaptureDstIp(cls, ip):
		pass
	@abstractmethod 
	def getCaptureDstIp(cls):
		pass
	@abstractmethod 
	def setCaptureDstHost(cls, host):
		pass
	@abstractmethod 
	def getCaptureDstHost(cls):
		pass
	@abstractmethod 
	def setCaptureDstPort(cls, port):
		pass
	@abstractmethod 
	def getCaptureDstPort(cls):
		pass
	@abstractmethod 
	def setReplayTargetIp(cls, ip):
		pass
	@abstractmethod 
	def getReplayTargetIp(cls):
		pass
	@abstractmethod 
	def setReplayTargetPort(cls, port):
		pass
	@abstractmethod 
	def getReplayTargetPort(cls):
		pass
	@abstractmethod 
	def setReplayStarttime(cls, stime):
		pass
	@abstractmethod 
	def getReplayStarttime(cls):
		pass
	@abstractmethod 
	def setReplayEndtime(cls, etime):
		pass
	@abstractmethod 
	def getReplayEndtime(cls):
		pass
	@abstractmethod 
	def setSaveType(cls, type):
		pass
	@abstractmethod 
	def getSaveType(cls):
		pass
	@abstractmethod 
	def setSaveWriteWay(cls, way):
		pass
	@abstractmethod 
	def getSaveWriteWay(cls):
		pass
	@abstractmethod 
	def setSaveMaxLine(cls, num):
		pass
	@abstractmethod 
	def getSaveMaxLine(cls):
		pass

class Rules(IRules):
	__stop=''
	__action=''
	__sourceIp=''
	__sourceHost=''
	__sourcePort=''
	__dstIp=''
	__dstHost=''
	__dstPort=''
	__targetIp=''
	__targetPort='80'
	__startTime=''
	__endTime=''
	__saveType='pcap'
	__writeWay='time'
	__maxLine=100
	
	@classmethod 
	def setStop(cls, flg):
		cls.__stop = flg
	@classmethod 
	def getStop(cls):
		return cls.__stop
	@classmethod 
	def setAction(cls, act):
		cls.__action = act
	@classmethod 
	def getAction(cls):
		return cls.__action
	@classmethod
	def setCaptureSourceIp(cls, ip):
		cls.__sourceIp = ip
	@classmethod
	def getCaptureSourceIp(cls):
		return cls.__sourceIp
	@classmethod 
	def setCaptureSourceHost(cls, host):
		cls.__sourceHost = host
	@classmethod 
	def getCaptureSourceHost(cls):
		return cls.__sourceHost
	@classmethod 
	def setCaptureSourcePort(cls, port):
		cls.__sourcePort = port
	@classmethod 
	def getCaptureSourcePort(cls):
		return cls.__sourcePort
	@classmethod 
	def setCaptureDstIp(cls, ip):
		cls.__dstIp = ip
	@classmethod 
	def getCaptureDstIp(cls):
		return cls.__dstIp
	@classmethod 
	def setCaptureDstHost(cls, host):
		cls.__dstHost = host
	@classmethod 
	def getCaptureDstHost(cls):
		return cls.__dstHost
	@classmethod 
	def setCaptureDstPort(cls, port):
		cls.__dstPort = port
	@classmethod 
	def getCaptureDstPort(cls):
		return cls.__dstPort
	@classmethod 
	def setReplayTargetIp(cls, ip):
		cls.__targetIp = ip
	@classmethod 
	def getReplayTargetIp(cls):
		return cls.__targetIp
	@classmethod 
	def setReplayTargetPort(cls, port):
		cls.__targetPort = port
	@classmethod 
	def getReplayTargetPort(cls):
		return cls.__targetPort
	@classmethod 
	def setReplayStarttime(cls, stime):
		cls.__startTime = stime
	@classmethod 
	def getReplayStarttime(cls):
		return cls.__startTime
	@classmethod 
	def setReplayEndtime(cls, etime):
		cls.__endTime = etime
	@classmethod 
	def getReplayEndtime(cls):
		return cls.__endTime
	@classmethod 
	def setSaveType(cls, type):
		cls.__saveType = type
	@classmethod 
	def getSaveType(cls):
		return cls.__saveType
	@classmethod 
	def setSaveWriteWay(cls, way):
		cls.__writeWay = way
	@classmethod 
	def getSaveWriteWay(cls):
		return cls.__writeWay
	@classmethod 
	def setSaveMaxLine(cls, num):
		cls.__maxLine = num
	@classmethod 
	def getSaveMaxLine(cls):
		return cls.__maxLine

class PcapRules(Rules):    
	instance=None
	mutex=threading.Lock()

	def __init__(self):
		pass

	@staticmethod
	def GetInstance():
		if(PcapRules.instance==None):
			PcapRules.mutex.acquire()
			if(PcapRules.instance==None):
				PcapRules.instance=PcapRules()
			else:
				print 'exist instance'
				pass
			PcapRules.mutex.release()
		else:
			pass
		   
		return PcapRules.instance

def UnitTest():
	rule = PcapRules()
	rule = PcapRules.GetInstance()
	rule.setCaptureSourceIp('111.12.13.14')
	print rule.getCaptureSourceIp()
	rule = PcapRules.GetInstance()
	print rule.getCaptureSourceIp()

if __name__=='__main__': 
	UnitTest()