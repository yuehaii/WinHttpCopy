#! python2
#coding:utf8

from abc import ABCMeta, abstractmethod
import time
import sys
import select
import socket
import os 
import sys
import urlparse
import re
import urllib
import urllib2
import struct
import dpkt
import pcap
import json 
from Rule.Rules import *
from File.Files import *

class IPktsParser:
	__metaclass__ = ABCMeta 

	@abstractmethod 
	def parseCapStream(cls, filename):
		pass

	@abstractmethod 
	def replayCapStream(cls, http):
		pass

class PktsParser(IPktsParser): 
	@classmethod 
	def __getMissData(cls, filename, index):
		reparseAckNumber = 0
		reparseNextSeqNumber = 0
		allData = ''
		allDataSplited = [] 

		pcaphdrlen = 24
		pkthdrlen=16
		linklen=14
		iphdrlen=20
		tcphdrlen=20
		stdtcp = 20
		layerdict = {'FILE':0, 'MAXPKT':1, 'HEAD':2, 'LINK':3, 'IP':4, 'TCP':5, 'DATA':6, 'RECORD':7}

		file = open(filename, "rb") 
		datahdr = file.read(pcaphdrlen)
		(tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", datahdr)

		if lt == 0x71:
			linklen = 16
		else:
			linklen = 14

		data = file.read(pkthdrlen)
		indexCur = 0
		while data:
			indexCur = indexCur + 1
			
			(sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)
			link = file.read(linklen)
			ipdata = file.read(iphdrlen)
			tcpdata = file.read(stdtcp)	
			(sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)
			tcpdatalen = iplensave-linklen-iphdrlen-stdtcp
			httpdata = file.read(tcpdatalen)

			if indexCur == index:
				reparseAckNumber = ack_seq
				reparseNextSeqNumber = tcpdatalen + seq
				allData += str(httpdata)
			if ack_seq == reparseAckNumber and seq == reparseNextSeqNumber:
				reparseNextSeqNumber = tcpdatalen + seq
				allData += str(httpdata)

			data = file.read(pkthdrlen)
		allDataSplited = allData.split("\n");
		return allDataSplited

	@classmethod 
	def __getHostname(cls, v):
		host=''
		partArr = v.split(': ');
		lenArr = len(partArr)
		if lenArr >= 2 :
			paraKey = partArr[0]
			paraVal = ''
			for ktype, vtype in enumerate(partArr):
				if ktype != 0:
					paraVal = paraVal + vtype.replace("\r","").replace("\n","")
			if paraKey == 'Host':
				host = paraVal.replace("\r","").replace("\n","")
				return host
		return None

	@classmethod 
	def __getHeaderdata(cls, headerdata, v):
		partArr = v.split(': ');
		lenArr = len(partArr)
		if lenArr >= 2 :
			paraKey = partArr[0]
			paraVal = ''
			for ktype, vtype in enumerate(partArr):
				if ktype != 0:
					paraVal = paraVal + vtype.replace("\r","").replace("\n","")
			headerdata[paraKey] = paraVal
		return headerdata

	@classmethod 
	def __getPostdata(cls, v):
		postdata = {}
		partArr = v.split('&');
		for kpara, vpara in enumerate(partArr):
			lenArr = len(vpara)
			if lenArr >= 1 :
				partArr2 = vpara.split('=');
				lenArr2 = len(partArr)
				if lenArr2 >= 2 :
					paraKey = partArr2[0]
					paraVal = ''
					for ktype, vtype in enumerate(partArr2):
						if ktype != 0:
							paraVal = paraVal + vtype.replace("\r","").replace("\n","")
					postdata[paraKey] = paraVal
		return postdata

	@classmethod 
	def __getHttpType(cls, v):
		httptype = ''
		partArr = v.split(' ');
		lenArr = len(partArr)
		if lenArr >= 3 and partArr[lenArr - 1].find('HTTP/') != -1:
			httptype = partArr[0].replace("\r","").replace("\n","")
		return httptype

	@classmethod 
	def __getUriPath(cls, v):
		uriPath=''
		partArr = v.split(' ');
		lenArr = len(partArr)
		if lenArr >= 3 and partArr[lenArr - 1].find('HTTP/') != -1:
			for ktype, vtype in enumerate(partArr):
				if ktype != 0 and ktype != lenArr - 1:
					uriPath = uriPath + vtype.replace("\r","").replace("\n","")
		return uriPath

	@classmethod 
	def __resendExceptionPost(cls, fullurl, headerdata, postdata):
		if len(postdata) <= 0:
			return

		data = urllib.urlencode(postdata).encode('utf-8')
		request = urllib2.Request(fullurl, data)
		for (k, v) in headerdata.items():
			request.add_header(k, v)
		request = urllib2.urlopen(request)
		
	@classmethod 
	def __resendExceptionGet(cls, fullurl, headerdata):
		req = urllib2.Request(fullurl)
		for (k, v) in headerdata.items():
			req.add_header(k, v)
		res = urllib2.urlopen(req)

	@classmethod 
	def __resendExceptionDelete(cls, fullurl, headerdata, postdata):
		if len(postdata) <= 0:
			return
		data = urllib.urlencode(postdata).encode('utf-8')
		request = urllib2.Request(fullurl, data)
		for (k, v) in headerdata.items():
			request.add_header(k, v)
		request.get_method = lambda:'DELETE'    
		request = urllib2.urlopen(request)

	@classmethod 
	def __resendExceptionPut(cls, fullurl, headerdata, postdata):
		if len(postdata) <= 0:
			return
		data = urllib.urlencode(postdata).encode('utf-8')
		request = urllib2.Request(fullurl, data)
		for (k, v) in headerdata.items():
			request.add_header(k, v)
		request.get_method = lambda:'PUT'    
		request = urllib2.urlopen(request)

	@classmethod 
	def __resendExceptionHead(cls, fullurl, headerdata):
		req = urllib2.Request(fullurl)
		for (k, v) in headerdata.items():
			request.add_header(k, v)
		req.get_method = lambda: 'HEAD'
		res = urllib2.urlopen(req)

	@classmethod 
	def __reParseExceptionStream(cls, filename, index):
		httptype = ''
		uriPath=''
		host=''
		postdata = {}
		headerdata = {}
		allDataSplited = cls.__getMissData(filename, index)
		for k, v in enumerate(allDataSplited):
			if len(v) <= 1:
				continue
			if v.find(': ') != -1:
				cls.__getHeaderdata(headerdata, v)
				thost = cls.__getHostname(v)
				if thost != None:
					host = thost
			elif v.find('&') != -1:
				postdata = cls.__getPostdata(v)
			elif v.find(' ') != -1:
				httptype = cls.__getHttpType(v)
				uriPath = cls.__getUriPath(v)
		if len(httptype) <= 0 or len(uriPath) <= 0 or len(host) <= 0:
			return
		fullurl = 'http://' + host + uriPath

		if httptype == 'POST':
			cls.__resendExceptionPost(fullurl, headerdata, postdata)
		elif httptype == 'GET':
			cls.__resendExceptionGet(fullurl, headerdata)
		elif httptype == 'DELETE':
			cls.__resendExceptionDelete(fullurl, headerdata, postdata)
		elif httptype == 'PUT':
			cls.__resendExceptionPut(fullurl, headerdata, postdata)
		elif httptype == 'HEAD':
			cls.__resendExceptionHead(fullurl, headerdata)
		else:
			return

	@classmethod 
	def parseCapStream(cls, filename):
		handl = file(filename, "rb")
		pcap = dpkt.pcap.Reader(handl)
		index = 0
		for ts, pkt in pcap:
			index = index + 1
			eth = dpkt.ethernet.Ethernet(pkt) 
			if eth.type != dpkt.ethernet.ETH_TYPE_IP:
				continue

			ip = eth.data
			if ip.p != dpkt.ip.IP_PROTO_TCP: 
				continue

			tcp = ip.data 
			if len(tcp.data) <= 0 or tcp.dport != 80:
				continue

			try:
				http = dpkt.http.Request(tcp.data) 
				cls.replayCapStream(http)
			except dpkt.dpkt.NeedData:
				Log.saveDataToFile('dpkt.dpkt.NeedData Exception!\n')
				Log.saveDataToFile("cause exception tcp.data:" + str(tcp.data) + "\n")
				cls.__reParseExceptionStream(filename, index)
				continue
			except dpkt.dpkt.UnpackError:
				Log.saveDataToFile('dpkt.dpkt.UnpackError Exception!\n')
				continue
			except Exception as err: 
				Log.saveDataToFile('dpkt.dpkt.other Exception!' + str(err) + "\n")
				continue

	@classmethod 
	def __replayGet(cls, http):
		fulluri = 'http://' + http.headers['host'] + http.uri
		req = urllib2.Request(fulluri)

		for key, val in http.headers.items():
			req.add_header(key, val)

		res = urllib2.urlopen(req)

	@classmethod 
	def __replayPost(cls, http):
		if len(http.body) <= 1:
			return

		postdata = {}
		oridata = str(http.body)
		if oridata.find('&') != -1:
			partArr = oridata.split('&');
			for kpara, vpara in enumerate(partArr):
				lenArr = len(vpara)
				if lenArr >= 1 :
					partArr2 = vpara.split('=');
					lenArr2 = len(partArr)
					if lenArr2 >= 2 :
						paraKey = partArr2[0]
						paraVal = ''
						for ktype, vtype in enumerate(partArr2):
							if ktype != 0:
								paraVal = paraVal + vtype.replace("\r","").replace("\n","")
						postdata[paraKey] = paraVal
		Log.saveDataToFile("postdata:" + str(postdata))

		fulluri = 'http://' + http.headers['host'] + http.uri
		data = urllib.urlencode(postdata).encode('utf-8')
		request = urllib2.Request(fullurl, data)
		for key, val in http.headers.items():
			request.add_header(key, val)
		request = urllib2.urlopen(request)

	@classmethod 
	def __replayPut(cls, http):
		fulluri = 'http://' + http.headers['host'] + http.uri
		if len(http.body) <= 1:
			return

		putdata = {}
		oridata = str(http.body)
		if oridata.find('&') != -1:
			partArr = oridata.split('&');
			for kpara, vpara in enumerate(partArr):
				lenArr = len(vpara)
				if lenArr >= 1 :
					partArr2 = vpara.split('=');
					lenArr2 = len(partArr)
					if lenArr2 >= 2 :
						paraKey = partArr2[0]
						paraVal = ''
						for ktype, vtype in enumerate(partArr2):
							if ktype != 0:
								paraVal = paraVal + vtype.replace("\r","").replace("\n","")
						putdata[paraKey] = paraVal

		data = urllib.urlencode(putdata).encode('utf-8')
		request = urllib2.Request(fulluri, data)

		for key, val in http.headers.items():
			request.add_header(key, val)

		request.get_method = lambda:'PUT'    
		request = urllib2.urlopen(request)

	@classmethod 
	def __replayDelete(cls, http):
		fulluri = 'http://' + http.headers['host'] + http.uri
		if len(http.body) <= 1:
			return

		putdata = {}
		oridata = str(http.body)
		if oridata.find('&') != -1:
			partArr = oridata.split('&');
			for kpara, vpara in enumerate(partArr):
				lenArr = len(vpara)
				if lenArr >= 1 :
					partArr2 = vpara.split('=');
					lenArr2 = len(partArr)
					if lenArr2 >= 2 :
						paraKey = partArr2[0]
						paraVal = ''
						for ktype, vtype in enumerate(partArr2):
							if ktype != 0:
								paraVal = paraVal + vtype.replace("\r","").replace("\n","")
						putdata[paraKey] = paraVal

		Log.saveDataToFile("deldata:" + str(putdata))
		data = urllib.urlencode(putdata).encode('utf-8')
		request = urllib2.Request(fulluri, data)

		for key, val in http.headers.items():
			request.add_header(key, val)

		request.get_method = lambda:'DELETE'    
		request = urllib2.urlopen(request)

	@classmethod 
	def __replayHead(cls, http):
		fulluri = 'http://' + http.headers['host'] + http.uri
		req = urllib2.Request(fulluri)

		for key, val in http.headers.items():
			req.add_header(key, val)
		req.get_method = lambda: 'HEAD'
		res = urllib2.urlopen(req)

	@classmethod 
	def replayCapStream(cls, http):
		if len(http.method) <= 0 or len(http.headers['host']) <= 0 or len(http.uri) <= 0:
			return

		if http.method == 'GET':
			cls.__replayGet(http)
		elif http.method == 'POST':
			cls.__replayPost(http)
		elif http.method == 'PUT':
			cls.__replayPut(http)
		elif http.method == 'DELETE':
			cls.__replayDelete(http)
		elif http.method == 'HEAD':
			cls.__replayHead(http)

def UnitTest():
	th = PktsParser()

if __name__=='__main__': 
	UnitTest()
