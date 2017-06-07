#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import threading
import sys
sys.path.append("..")
from ParaAnalyzer import *
from Capture.Capture import *
from Replay.Replay import *

class IThread:
	__metaclass__ = ABCMeta 
	
	@abstractmethod 
	def stop(cls):
		pass

	@abstractmethod 
	def task(cls):
		pass

class ThreadTask(threading.Thread, IThread):  
	__stopFlag = 0

	def __init__(self):  
		threading.Thread.__init__(self)

	@classmethod
	def isTaskStop(cls):
		return cls.__stopFlag

	@classmethod
	def run(cls):
		cls.task()

	@classmethod
	def stop(cls):
		cls.__stopFlag = 1
		print 'Task stop stopFlag:'+str(cls.__stopFlag)+'\n'

	@classmethod 
	def task(cls):
		if cls.__stopFlag != 1:
			print 'Task begin\n'
		else:
			print 'Task aborted\n'

class CapThread(ThreadTask): 
	__cap = None

	@classmethod 
	def task(cls):
		cls.__cap = Capture()
		cls.__cap.startCapture()

	@classmethod
	def stop(cls):
		cls.__cap.stopCapture()
		cls.__stopFlag = 1

class ReplayThread(ThreadTask): 
	__rep = None

	@classmethod 
	def task(cls):
		print 'ReplayThread begin'
		cls.__rep = Replay()
		cls.__rep.startReplay()

	@classmethod
	def stop(cls):
		cls.__rep.stopReplay()
		cls.__stopFlag = 1

class MainThread(ThreadTask): 
	__capthread = []
	__repthread = []

	@classmethod 
	def __isCaptureCmd(cls):
		rule = PcapRules.GetInstance()
		if rule.getAction() == 'c' or rule.getAction() == 'capture':
			if len(rule.getCaptureDstIp()) <=0:
				print 'Please input destination ip before capture!'
				return False
			for key, val in enumerate(cls.__capthread):
				if val.isTaskStop() == 0:
					#TODO: do not support multiple sniff 
					print 'Please stop previous before start new capture!'
					return False
			rule.setAction('')
			return True
		else:
			return False

	@classmethod 
	def __isStopCaptureCmd(cls):
		rule = PcapRules.GetInstance()
		if (rule.getAction() == 'c' or rule.getAction() == 'capture') and rule.getStop() == '1' and len(cls.__capthread) > 0:
			return True
		else:
			return False
		
	@classmethod 
	def __isReplayCmd(cls):
		rule = PcapRules.GetInstance()
		if rule.getAction() == 'r' or rule.getAction() == 'replay':
			if len(rule.getReplayTargetIp()) <=0 or len(rule.getReplayTargetPort()) <=0:
				print 'Please input target ip and port before replay!'
				return False
			rule.setAction('')
			return True
		else:
			return False

	@classmethod 
	def __isStopReplayCmd(cls):
		rule = PcapRules.GetInstance()
		if (rule.getAction() == 'r' or rule.getAction() == 'replay') and rule.getStop() == '1' and len(cls.__repthread) > 0:
			return True
		else:
			return False

	@classmethod 
	def __stopSubThread(cls, flag):
		rule = PcapRules.GetInstance()
		if flag == 'cap':
			rule.setStop('0')
			for key, val in enumerate(cls.__capthread):
				val.stop()
				del cls.__capthread[key]
		elif flag == 'rep':
			rule.setStop('0')
			for key, val in enumerate(cls.__repthread):
				val.stop()
				del cls.__repthread[key]

	@classmethod 
	def __cleanQuit(cls):
		cls.__stopSubThread('cap')
		cls.__stopSubThread('rep')
		time.sleep(1)
		sys.exit(1)

	@classmethod 
	def task(cls):
		while cls.isTaskStop() != 1:
			cmdStr = raw_input("\nPlease input capture or replay command:\n") 
			if cmdStr == 'quit' or cmdStr == '-q':
				cls.__cleanQuit()
			
			para = ParaAnalyzer()
			ret = para.parseParameter(cmdStr)
			if ret == True:
				rule = PcapRules.GetInstance()
				if cls.__isStopReplayCmd() == True:
					cls.__stopSubThread('rep')
				elif cls.__isStopCaptureCmd() == True:
					cls.__stopSubThread('cap')
				elif cls.__isCaptureCmd() == True:
					capthread = CapThread()
					capthread.start()
					cls.__capthread.append(capthread)
				elif cls.__isReplayCmd() == True:
					repthread = ReplayThread()
					repthread.start()
					cls.__repthread.append(repthread)
			else:
				pass

			time.sleep(1)


def UnitTest():
	th = MainThread()
	th.start()
	#th.stop()

if __name__=='__main__': 
	UnitTest()
