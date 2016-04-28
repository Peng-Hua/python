from socket import *
import struct
from uuid import getnode
from random import randint
import binascii

def transMac(data):
	mac=''
	for i in range(0,len(data)):
		tmp = str(hex(data[i]))
		mac += tmp[2:]
		mac += ':'
	mac = mac[:-1]
	return mac

def transXid(data):
	xid = ''
	for i in range(0,len(data)):
		tmp = str(hex(data[i]))
		xid += tmp[2:]
	xid = '0x'+xid
	return xid

class DHCPDiscover:
	def __init__(self):
		self.xid = self.getXid()
		self.mac = self.getMac()
		self.printDiscover()
		
	def printDiscover(self):
		print("[SEND] DHCP DISCOVER")
		print("MAC: " + transMac(self.mac))
		print("TransationID: " + transXid(self.xid))
		print('')

	def buildPacket(self):
		packet  = b''
		packet  = b'\x01'                 #Message type
		packet += b'\x01'                 #Hardware type
		packet += b'\x06'                 #Hardware address length
		packet += b'\x00'                 #Hops
	
		packet += self.xid                #Transaction ID
		packet += b'\x00\x00'             #Seconds elapsed
		packet += b'\x80\x00'             #Bootp flags + reserved flags
		packet += inet_aton('0.0.0.0')    #Client IP
		packet += inet_aton('0.0.0.0')    #Your IP
		packet += inet_aton('0.0.0.0')    #Next server IP
		packet += inet_aton('0.0.0.0')    #Relay agent IP
		packet += self.mac                #Client MAC address
		packet += b'\x00' * 202           #Client hardware address padding
		packet += b'\x63\x82\x53\x63'     #Magic cookie
		packet += b'\x35\x01\x01'         #Option DHCP Discover
		packet += b'\x37\x03\x03\x01\x06' #Parameter Request List
		packet += b'\xff'                 #End Option
		return packet

	def getXid(self):
		xid = b''
		for i in range(4):
			t = randint(0, 255)
			xid += struct.pack('!B', t)
		return xid

	def getMac(self):
		mac = str(getnode())
		mac = mac[0:12]
		macBytes = b''
		macBytes = binascii.unhexlify(mac)
		return macBytes

class DHCPOffer:
	def __init__(self,data,xid, serverIP):
		self.isRecv=1
		self.xid = xid
		self.dhcpServer = ''
		self.offerIP = ''
		self.serverIP = serverIP
		self.printOffer()
	
	def printOffer(self):
		print("[RECEIVE] DHCP OFFER")
		self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
		self.dhcpServer = '.'.join(map(lambda x:str(x), data[263:267]))	

		print('MAC: ' + transMac(data[28:34]))
		print('TransationID: ' + transXid(data[4:8]))
		print('Offer IP: ' + '.'.join(map(lambda x:str(x), data[16:20])))
		print('Next Server IP: ' + '.'.join(map(lambda x:str(x), data[20:24])))
		print('Subnet Mask: '  + '.'.join(map(lambda x:str(x), data[245:249])))
		print('Router: '  + '.'.join(map(lambda x:str(x), data[251:255])))
		print('DHCP Server: '  + '.'.join(map(lambda x:str(x), data[263:267])))
		print('DNS1 server: '  + '.'.join(map(lambda x:str(x), data[269:273])))
		print('DNS2 server: '  + '.'.join(map(lambda x:str(x), data[275:279])))
		print('DNS3 server: '  + '.'.join(map(lambda x:str(x), data[281:285])))
		print('')
		
class DHCPRequest:
	def __init__(self,xid,mac,serverIP,dhcpServer,offerIP):
		self.xid = xid
		self.mac = mac
		self.serverIP = serverIP
		self.dhcpServer = dhcpServer
		self.offerIP = offerIP
		self.printRequest()

	def printRequest(self):
		print('[SEND] DHCP REQUEST')
		print('MAC: ' + transMac(self.mac))
		print('TransationID: ' + transXid(self.xid))
		print('ServerIP: ' + self.serverIP)
		print('OfferIP: ' + self.offerIP)
		print('DHCPServer: ' + self.dhcpServer)
		print('')
		
	def buildPacket(self):
		packet  = b''
		packet += b'\x01'                  #Message type
		packet += b'\x01'                  #Hardware type
		packet += b'\x06'                  #Hardware address length
		packet += b'\x00'                  #Hops
		packet += self.xid                 #Transaction ID
		packet += b'\x00\x00'              #Seconds elapsed
		packet += b'\x00\x00'              #Bootp flags + reserved flags
		packet += inet_aton('0.0.0.0')     #Client IP
		packet += inet_aton('0.0.0.0')     #Your IP
		packet += inet_aton(self.serverIP) #Next server IP
		packet += inet_aton('0.0.0.0')     #Relay agent IP
		packet += self.mac                 #Client MAC address
		packet += b'\x00' * 202            #Client hardware address padding
		packet += b'\x63\x82\x53\x63'      #Magic cookie
		packet += b'\x35\x01\x03'          #Option DHCP Request
		packet += b'\x32\x04'              #requested
		packet += inet_aton(self.offerIP)
		packet += b'\x36\x04'              #DHCP Server
		packet += inet_aton(self.dhcpServer)
		packet += b'\xff' 
		return packet

class DHCPACK:

	def __init__(self,data,xid, serverIP):
		self.xid = xid
		self.serverIP=serverIP
		self.unpack(data)
		self.printAck()
	
	def printAck(self):
		print("[RECEIVES] DHCP ACK")
		print("Transation ID: "+transXid(data[4:8]))
		print("MAC: "+transMac(data[28:34]))
		print("Offer IP: " + '.'.join(map(lambda x:str(x), data[16:20])))
		print("Next Server IP: " + '.'.join(map(lambda x:str(x), data[20:24])))
		print("Subnet Mask:"  + '.'.join(map(lambda x:str(x), data[245:249])))
		print("Router:"  + '.'.join(map(lambda x:str(x), data[251:255])))
		print("DHCP Server:"  + '.'.join(map(lambda x:str(x), data[263:267])))
		print("DNS1 server:"  + '.'.join(map(lambda x:str(x), data[269:273])))
		print("DNS2 server:"  + '.'.join(map(lambda x:str(x), data[275:279])))
		print("DNS3 server:"  + '.'.join(map(lambda x:str(x), data[281:285])))
		print('')
		
if __name__ =='__main__':

	print('===== DHCP CLIENT =====')
	dhcps = socket(AF_INET, SOCK_DGRAM)
	dhcps.setsockopt(SOL_SOCKET, SO_BROADCAST, 1) 
	dhcps.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)
	serverIP = "192.168.1.1"
	try:
		dhcps.bind(('0.0.0.0', 68))
	except Exception as e:
		print(e)
		dhcps.close()
		exit()
	dhcps.settimeout(20)
	
	discoverPkt = DHCPDiscover()
	dhcps.sendto(discoverPkt.buildPacket(), ('<broadcast>', 67))
	
	try:
		while True:
			data = dhcps.recv(1024)
			offerPkt = DHCPOffer(data, discoverPkt.xid, serverIP)
			if offerPkt.isRecv == 1:
				break
		requestPkt = DHCPRequest(discoverPkt.xid,discoverPkt.mac,offerPkt.serverIP,offerPkt.dhcpServer,offerPkt.offerIP)
		dhcps.sendto(requestPkt.buildPacket(),('<broadcast>',67))
		data = dhcps.recv(1024)
		ackPacket = DHCPACK(data,discoverPkt.xid,serverIP)
	except timeout as e:
		print(e)
	
	dhcps.close()
	exit()
