#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import time
import sys
import os 
import sys
import struct
import dpkt
import pcap
import json 
from Rule.Rules import *
print "Starting..." 
from scapy.all import * 

class IFiles:
	__metaclass__ = ABCMeta 

	@abstractmethod 
	def genSaveFilePath(cls):
		pass

	@abstractmethod 
	def saveDataToFile(cls, datas):
		pass

	@abstractmethod 
	def getDirFiles(cls, dir):
		pass

class Log(IFiles):
	@staticmethod 
	def genSaveFilePath():
		dir = '../log/' 
		if False == os.path.exists(dir):
			os.makedirs(dir)
		tm = time.strftime('%Y-%m-%d %H',time.localtime(time.time()))
		return dir + tm + '.log'
		

	@staticmethod
	def saveDataToFile(datas):
		f = open(Log.genSaveFilePath(), 'a') 
		f.write(str(datas)+'\n')
		f.close()

	@classmethod 
	def getDirFiles(cls, dir):
		pass
		
class Files(IFiles): 
	dir = '' 
	type = 'pcap' 

	@classmethod 
	def __init__(cls):
		pass

	@classmethod 
	def __sortFiles(cls, filelists): 
		for i in range(len(filelists)):
			if i < (len(filelists)-1) and filelists[i][0] > filelists[i+1][0]:
				temp = filelists[i+1]
				filelists[i+1] = filelists[i]
				filelists[i] = temp
			else:
				continue
		return filelists

	@classmethod 
	def __getOneDirFiles(cls, dir):
		dir_log = dir
		filelists = [(os.path.getctime(dir_log  + folder),dir_log + folder) for folder in os.listdir(dir_log)]

		cyctimes = len(filelists)
		i = 0
		seqFiles = None
		while(i < cyctimes): 
			i = i + 1
			seqFiles = cls.__sortFiles(filelists)
		return seqFiles

	@classmethod 
	def getDirFiles(cls, dir, outarray):
		seqFiles = cls.__getOneDirFiles(dir)
		if seqFiles != None:
			for key, val in enumerate(seqFiles):
				if False == os.path.isdir(val[1]): 
					outarray.append(val[1])
		filelist = os.listdir(dir)  
		for num in range(len(filelist)):  
			filename=filelist[num]  
			if os.path.isdir(dir + filename):  
				cls.getDirFiles(dir + filename + "/", outarray)

		return seqFiles

	@classmethod 
	def genSaveFilePath(cls):
		pass

	@classmethod 
	def saveDataToFile(cls, datas):
		pass 

class PcapFile(Files): 
	@classmethod 
	def __init__(cls): 
		cls.dir = '../file/' 
		rule = PcapRules.GetInstance()
		cls.dir += rule.getCaptureDstIp() + "/"
		if len(rule.getCaptureDstPort()) > 0:
			cls.dir += rule.getCaptureDstPort() + "/"
		if len(rule.getCaptureSourceIp()) > 0:
			cls.dir += rule.getCaptureSourceIp() + "/"
		if len(rule.getCaptureSourcePort()) > 0:
			cls.dir += rule.getCaptureSourcePort() + "/"
		if False == os.path.exists(cls.dir):
			os.makedirs(cls.dir)

		if len(rule.getSaveType()) > 0:
			cls.type = rule.getSaveType()

	@classmethod 
	def genSaveFilePath(cls):
		curt = str(time.time())
		pathname = cls.dir + curt + "." + cls.type;
		if True == os.path.exists(pathname):
			pathname = cls.dir + curt + ".1." + cls.type; 
		return pathname

	@classmethod 
	def saveDataToFile(cls, datas):
		wrpcap(cls.genSaveFilePath(), datas)  

def UnitTest():
	Log.saveDataToFile('test log!')

if __name__=='__main__': 
	UnitTest()
