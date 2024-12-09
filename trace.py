import argparse
import sys
import socket
import traceback
import ipaddress

parser = argparse.ArgumentParser(description="Network Emulator")

parser.add_argument("-a", "--routetrace_port", type=int, required=True, dest="rtPort")
parser.add_argument("-b", "--source_hostname", type=str, required=True, dest="srcHost")
parser.add_argument("-c", "--source_port", type=int, required=True, dest="srcPort")
parser.add_argument("-d", "--destination_hostname", type=int, required=True, dest="destHost")
parser.add_argument("-e", "--destination_port", type=int, required=True, dest="destPort")
parser.add_argument("-f", "--debug_option", type=int, required=True, dest="debug")

args = parser.parse_args()

# check port numbers
if 2049 > args.rtPort or args.rtPort > 65536:
    print("Routetrace port out of range.")
    sys.exit()

# open port (to listen on only?)
hostname = socket.gethostname()
ipAddr = socket.gethostbyname(hostname)

# get addresses
hostAddr = (ipaddress.ip_address(ipAddr), args.port)
srcAddr = (ipaddress.ip_address(socket.gethostbyname(args.srcHost)), args.srcPort)
destAddr = (ipaddress.ip_address(socket.gethostbyname(args.destHost)), args.destPort)

# make the first bytes of the packet
# route trace packet format: type 1B, srcIP 4B, srcPort 2B, destIP 4B, destPort 2B, senderIP 4B, senderPort 2B, TTL 4B
# get src and dest pairs
pType = ord('T').to_bytes(1, 'big')
srcIP = socket.htonl(int(srcAddr[0])).to_bytes(4, 'big')
srcPort = socket.htons(srcAddr[1]).to_bytes(2, 'big')
destIP = socket.htonl(int(destAddr[0])).to_bytes(4, 'big')
destPort = socket.htons(destAddr[1]).to_bytes(2, 'big')
senderIP = socket.htonl(int(hostAddr[0])).to_bytes(4, 'big')
senderPort = socket.htons(hostAddr[1]).to_bytes(2, 'big')
packetStart = pType + srcIP + srcPort + destIP + destPort + senderIP + senderPort

# open socket
try:
    recSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recSoc.bind(hostAddr)
    recSoc.setblocking(True)
except:
    print("An error occured binding the socket")
    print(traceback.format_exc())
    sys.exit()

# socket to send from (not the same one)
sendSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def routetrace():
    for i in range(20): # at most 20 nodes
        # send new packet
        sendRTPacket(i)
        
        # wait for response
        try:
            # try to recieve packet and handle it
            data, addr = recSoc.recvfrom(4096)

            handlePacket(data)
        except BlockingIOError:
            pass # Not sure what happened
        except KeyboardInterrupt:
            sys.exit()
        except:
            print("Something went wrong when listening for or interacting with packet.")
            print(traceback.format_exc())


# send the traceroute packet with specified time to live
def sendRTPacket(tTL):
    packet = packetStart + socket.htonl(tTL).to_bytes(4, 'big')
    src = (str(srcAddr[0]), srcAddr[1])
    sendSoc.sendto(packet, src)


# handles packets and prints if needed
def handlePacket(data):
    if data[0] != 79:
        return # wrong packet type
    
    # print responders IP and port

    # print debug information if needed
    if args.debug == 1:
        pass

    # determine if responder is destination address if so exit



def cleanup():
    recSoc.close()
    sys.exit()

def main():
    routetrace()
    cleanup()

if __name__ == '__main__':
    main()

# 
# type: ignore