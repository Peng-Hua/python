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
	def __init__(self,data):
		self.xid = b''
		self.mac = b''
		self.unpack(data)
		self.printDiscover()
		
	def unpack(self,data):
		self.xid = data[4:8]
		self.mac = data[28:34]

	def printDiscover(self):
		print("[RECEIVE] DHCP DISCOVER")
		print("Transation ID: "+transXid(self.xid))
		print("MAC: "+transMac(self.mac))
		print('')
		
class DHCPOffer:
	def __init__(self,xid,mac):
		self.xid = xid
		self.mac = mac
		self.serverIP = '192.168.1.1'
		self.offerIP = '192.168.1.100'
		self.subnetMask = '255.255.255.0'
		self.leaseTime = 86400
		self.dhcpServer = '192.168.1.1'
		self.router = '192.168.1.1'
		self.dns1 = '9.7.10.15'
		self.dns2 = '9.7.10.16'
		self.dns3 = '9.7.10.18'
		self.printOffer()
		
	def printOffer(self):
		print("[SEND] DHCP OFFER")
		print("Transation ID:"+transXid(self.xid))
		print("MAC:"+transMac(self.mac))
		print("DhcpServer:"+self.dhcpServer)
		print("Offer IP:"+self.offerIP)
		print('')
	
	def buildPacketOffer(self):
		packet = b''
		packet += b'\x02'   #Message type
		packet += b'\x01'   #Hardware type
		packet += b'\x06'   #Hardware address length
		packet += b'\x00'   #Hops
	
		packet += self.xid                   #Transaction ID
		packet += b'\x00\x00'                #Seconds elapsed
		packet += b'\x00\x00'                #Bootp flags reserved flags
		packet += inet_aton('0.0.0.0')       #Client IP
		packet += inet_aton(self.offerIP)    #Your IP
		packet += inet_aton(self.serverIP)   #Next server IP
		packet += inet_aton('0.0.0.0')       #Relay agent IP
		packet += self.mac                   #Client MAC address
		packet += b'\x00' * 202
		packet += b'\x63\x82\x53\x63'        #Magic cookie
		packet += b'\x35\x01\x02'            #Option: DHCP Offer
		packet += b'\x01\x04'                #subnet mask 
		packet += inet_aton(self.subnetMask)
		packet += b'\x03\x04'                #router 
		packet += inet_aton(self.router) 
		packet += b'\x33\x04'                #leaseTime
		packet += (self.leaseTime).to_bytes(4,byteorder="big")
		packet += b'\x36\x04'                #server IP
		packet += inet_aton(self.dhcpServer)
		packet += b'\x06\x04'                #dns
		packet += inet_aton(self.dns1)
		packet += b'\x06\x04'                #dns
		packet += inet_aton(self.dns2)
		packet += b'\x06\x04'                #dns
		packet += inet_aton(self.dns3)
		packet += b'\xff'
		return packet

class DHCPRequest:
	def __init__(self,xid,data,serverIP):
		self.isRecv = 1
		self.xid = xid
		self.serverIP = serverIP
		self.unpack(data)
		self.printRequest()

		
	def unpack(self,data):
		serverIP = '.'.join(map(lambda x:str(x), data[20:24]))
		type = int(data[242])
		
		if self.xid != data[4:8] or self.serverIP != serverIP or type != 3:
			self.isRecv = 0
			print("[ERR] other DHCP REQUEST")
			return 

	def printRequest(self):
		print("[RECEIVE] DHCP REQUEST")
		print("TransationID: " + transXid(self.xid))
		print("MAC: " + transMac(data[28:34]))
		print("Server IP: " + self.serverIP)
		print("Offer IP: " + '.'.join(map(lambda x:str(x), data[245:249])))
		print('')
	
class DHCPACK:
	def __init__(self,xid,mac,offerIP,serverIP,subnetMask,router,leaseTime,dhcpServer,dns1, dns2, dns3):
		self.xid = xid
		self.mac = mac
		self.serverIP = serverIP
		self.offerIP = offerIP
		self.subnetMask = subnetMask
		self.leaseTime = leaseTime
		self.router = router
		self.dhcpServer=dhcpServer
		self.dns1 = dns1
		self.dns2 = dns2
		self.dns3 = dns3
		self.printAck()
		
	def printAck(self):
		print("[SEND] DHCP ACK")
		print("Transation ID: " + transXid(self.xid))
		print("MAC: " + transMac(self.mac))
		print("DhcpServer: " + self.dhcpServer)
		print("Offer IP: " + self.offerIP)
		print('')
		
	def buildPacketAck(self):
		packet = b''
		packet += b'\x02'                    #Message type
		packet += b'\x01'                    #Hardware type
		packet += b'\x06'                    #Hardware address length
		packet += b'\x00'                    #Hops
	
		packet += self.xid                   #Transaction ID
		packet += b'\x00\x00'                #Seconds elapsed
		packet += b'\x00\x00'                #Bootp flags + reserved flags
		packet += inet_aton('0.0.0.0')       #Client IP address
		packet += inet_aton(self.offerIP)    #Your IP address
		packet += inet_aton(self.serverIP)   #Next server IP address
		packet += inet_aton('0.0.0.0')       #Relay agent IP address
		packet += self.mac                   #Client MAC address
		packet += b'\x00' * 202              #Client hardware address padding
		packet += b'\x63\x82\x53\x63'        #Magic cookie
		packet += b'\x35\x01\x05'            #Option DHCP Message,DHCP ACK
		packet += b'\x01\x04'                #Option subnet Mask 
		packet += inet_aton(self.subnetMask) #subnet Mask
		packet += b'\x03\x04'                #router
		packet += inet_aton(self.router) 
		packet += b'\x33\x04'                #leaseTime 
		packet += (self.leaseTime).to_bytes(4,byteorder="big")
		packet += b'\x36\x04'                #DHCP Server
		packet += inet_aton(self.dhcpServer)	
		packet += b'\x06\x04'                #DNS1
		packet += inet_aton(self.dns1)
		packet += b'\x06\x04'                #DNS2
		packet += inet_aton(self.dns2)
		packet += b'\x06\x04'                #DNS3
		packet += inet_aton(self.dns3)
		packet += b'\xff'
		return packet	

if __name__ == '__main__':

	print('===== DHCP SERVER =====')
	dhcps = socket(AF_INET, SOCK_DGRAM)
	dhcps.setsockopt(SOL_SOCKET, SO_BROADCAST, 1) 
	dhcps.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)

	try:
		dhcps.bind(('', 67))    
	except Exception as e:
		print(e)
		dhcps.close()
		exit()
	dhcps.settimeout(20)
	
	try:
		while True:
			data = dhcps.recv(1024)
			discoverPkt = DHCPDiscover(data)
			offerPkt = DHCPOffer(discoverPkt.xid,discoverPkt.mac)
			dhcps.sendto(offerPkt.buildPacketOffer(), ('<broadcast>', 68))
			data = dhcps.recv(1024)
			requestPkt = DHCPRequest(discoverPkt.xid,data,offerPkt.serverIP)
			ackPacket = DHCPACK(discoverPkt.xid,discoverPkt.mac,offerPkt.offerIP,offerPkt.serverIP,offerPkt.subnetMask,offerPkt.router,offerPkt.leaseTime,offerPkt.dhcpServer,offerPkt.dns1, offerPkt.dns2, offerPkt.dns3)
			dhcps.sendto(ackPacket.buildPacketAck(), ('<broadcast>', 68))

			print('------------------')
	except timeout as e:
		print(e)
	except KeyboardInterrupt as e:
		print(e)
	dhcps.close()
	exit()
