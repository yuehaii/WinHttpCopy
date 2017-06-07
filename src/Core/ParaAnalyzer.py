#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import sys
import getopt
sys.path.append("..")
from Rule.Rules import *

class IParaAnalyzer:
	__metaclass__ = ABCMeta 
	
	@abstractmethod 
	def parseParameter(cls):
		pass

class ParaAnalyzer(IParaAnalyzer):
	shortPara = "hcr"
	longPara = ["stop", "help", "capture", "replay", "SrcIp=", "SrcHost=", "SrcPort=", "DstIp=", "DstHost=", "DstPort=", "TargetIp=", "TargetPort=", "Starttime=", "Endtime=", "SaveType=", "WriteWay=", "MaxLine="]
	
	@classmethod
	def help(cls):
		print 'Usage: \n'
		print 'Capture: -c/--capture --stop  --SrcIp=10.10.10.10 --SrcPort=80 --DstIp=10.10.10.11 --DstPort=80 --SaveType=pcap --WriteWay=time --MaxLine=100\n'
		print 'Replay: -r/--replay --stop  --TargetIp=10.10.10.10 --TargetPort=80 --Starttime=2017-04-07T10:00:00 --Endtime=2017-04-07T19:00:00\n'
		print 'Stop: -c/--capture --stop or -r/--replay --stop\n'
		print 'Exit: -q/quit\n'
		print 'Help: -h/--help\n'

	@classmethod
	def __checkTimeFormat(cls, value):
		IsCorrect = True
		listTime = value.split("T") 
		if len(listTime) != 2:
			IsCorrect = False
		else:
			ymd = listTime[0].split("-") 
			if len(ymd) != 3:
				IsCorrect = False
			else:
				if len(ymd[0]) != 4 or str(ymd[0]).isdigit() == False or int(ymd[0]) <= 0:
					IsCorrect = False
				elif len(ymd[1]) != 2 or str(ymd[1]).isdigit() == False or int(ymd[1]) <= 0:
					IsCorrect = False
				elif len(ymd[2]) != 2 or str(ymd[2]).isdigit() == False or int(ymd[2]) <= 0:
					IsCorrect = False

			hms = listTime[1].split(":") 
			if len(hms) != 3:
				IsCorrect = False
			else:
				if len(hms[0]) != 2 or str(hms[0]).isdigit() == False or int(hms[0]) < 0 or int(hms[0]) > 24:
					IsCorrect = False
				elif len(hms[1]) != 2 or str(hms[1]).isdigit() == False or int(hms[1]) < 0 or int(hms[1]) > 59:
					IsCorrect = False
				elif len(hms[2]) != 2 or str(hms[2]).isdigit() == False or int(hms[2]) < 0 or int(hms[2]) > 59:
					IsCorrect = False
		if IsCorrect == False:
			return False

	@classmethod
	def __checkParameters(cls, type, value):
		if type == '--SrcIp' or type == '--DstIp' or type == '--TargetIp':
			listip = value.split(".") 
			if len(listip) != 4:
				print 'Incorrect '+type+' parameter!'
				return False
		elif type == '--SrcPort' or type == '--DstIp' or type == '--TargetPort' or type == '--MaxLine':
			if str(value).isdigit() == False:
				print 'Incorrect '+type+' parameter!'
				return False
		elif type == '--Starttime' or type == '--Endtime':
			if cls.__checkTimeFormat(value) == False:
				print 'Incorrect '+type+' parameter!'
				return False
		return True

	@classmethod 
	def parseParameter(cls, cmds):
		retval = False
		try: 
			cmds = cmds.split(' ') 
			newcmds = []
			for idx,val in enumerate(cmds):
				if len(val) > 0 and val != ' ':
					newcmds.append(val)

			opts, args = getopt.getopt(newcmds, cls.shortPara, cls.longPara)
			rule = PcapRules.GetInstance()
			for opt, arg in opts:
				if cls.__checkParameters(opt, arg) == False:
					print cls.help()
					return False
				retval = True
				if opt in ("-h", "--help"):
					print cls.help()
					return False
				elif opt in ("--stop"):
					rule.setStop("1")
				elif opt in ("-c", "--capture", "-r", "--replay"):
					rule.setAction(opt.replace("-",""))
				elif opt == "--SrcIp":
					rule.setCaptureSourceIp(arg)
				elif opt == "--SrcHost":
					rule.setCaptureSourceHost(arg)
				elif opt == "--SrcPort":
					rule.setCaptureSourcePort(arg)
				elif opt == "--DstIp":
					rule.setCaptureDstIp(arg)
				elif opt == "--DstHost":
					rule.setCaptureDstHost(arg)
				elif opt == "--DstPort":
					rule.setCaptureDstPort(arg)
				elif opt == "--TargetIp":
					rule.setReplayTargetIp(arg)
				elif opt == "--TargetPort":
					rule.setReplayTargetPort(arg)
				elif opt == "--Starttime":
					rule.setReplayStarttime(arg)
				elif opt == "--Endtime":
					rule.setReplayEndtime(arg)
				elif opt == "--SaveType":
					rule.setSaveType(arg)
				elif opt == "--WriteWay":
					rule.setSaveWriteWay(arg)
				elif opt == "--MaxLine":
					rule.setSaveMaxLine(arg)
				else:  
					print("Incorrect Parameter: %s  ==> %s" %(opt, arg));
					cls.help()
					return False
			if retval == False:
				cls.help()
			return retval
		except getopt.GetoptError, err:
			print str(err)
			cls.help()
			return False

class PcapParaAnalyzer(ParaAnalyzer):
	pass


def UnitTest():
	#ParaAnalyzer.py --capture  --SrcIp=10.10.10.10 --SrcPort=80 --DstIp=10.10.10.11 --DstPort=80 
	#ParaAnalyzer.py --replay  --TargetIp=10.10.10.10 --TargetPort=80 --Starttime=2017-04-07T10:00:00 --Endtime=2017-04-07T19:00:00 --SaveType=pcap --WriteWay=time --MaxLine=100'
	para = ParaAnalyzer()
	para.parseParameter('--capture  --SrcIp=10.10.10.10 --SrcPort=80 --DstIp=10.10.10.11 --DstIp=80')
	rule = PcapRules.GetInstance()
	print rule.getCaptureSourceIp()
	print rule.getCaptureDstIp()
	print rule.getReplayTargetIp()

if __name__=='__main__': 
	UnitTest()
