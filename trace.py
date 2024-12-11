import argparse
import sys
import socket
import traceback
import ipaddress

parser = argparse.ArgumentParser(description="Network Emulator")

parser.add_argument("-a", "--routetrace_port", type=int, required=True, dest="rtPort")
parser.add_argument("-b", "--source_hostname", type=str, required=True, dest="srcHost")
parser.add_argument("-c", "--source_port", type=int, required=True, dest="srcPort")
parser.add_argument("-d", "--destination_hostname", type=str, required=True, dest="destHost")
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
hostAddr = (ipaddress.ip_address(ipAddr), args.rtPort)
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
    recSoc.bind((str(hostAddr[0]), hostAddr[1]))
    recSoc.setblocking(True)
except:
    print("An error occured binding the socket")
    print(traceback.format_exc())
    sys.exit()

# socket to send from (not the same one)
sendSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def routetrace():
    if args.debug == 0:
        print("Hop#  IP Port")
    else:
        print("Hop# SRCIP SRCPort DESTIP DESTPort")

    for tTL in range(20): # at most 20 nodes
        # send new packet
        sendRTPacket(tTL)
        
        # wait for response
        try:
            # try to recieve packet and handle it
            data, addr = recSoc.recvfrom(4096)
            print(data)
            handlePacket(data, tTL)
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

    # print packet information
    srcP = (str(srcAddr[0]), srcAddr[1])
    destP = (str(destAddr[0]), destAddr[1])

    if args.debug == 1:
        print("ROUTETRACE PACKET SENT:")
        print(f"{tTL} {srcP[0]}, {srcP[1]} {destP[0]}, {destP[1]}")



# handles packets and prints if needed
def handlePacket(data, tTL):
    print(data[0])
    if data[0] != 79:
        return # wrong packet type
    
    # print responders IP and port
    # get destination and source addresses
    srcIP = socket.ntohl(int.from_bytes(data[1:5], 'big'))
    srcPort = socket.ntohs(int.from_bytes(data[5:7], 'big'))
    srcKey = (ipaddress.ip_address(srcIP), srcPort)
    srcP = (str(ipaddress.ip_address(srcIP)), srcPort)

    destIP = socket.ntohl(int.from_bytes(data[7:11], 'big'))
    destPort = socket.ntohs(int.from_bytes(data[11:13], 'big'))
    destP = (str(ipaddress.ip_address(destIP)), destPort)

    if args.debug == 0:
        print(f"{tTL} {srcP[0]}, {srcP[1]}")
    else:
        print("RETURN PACKET RECIEVED:")
        print(f"{tTL} {srcP[0]}, {srcP[1]} {destP[0]}, {destP[1]}")
    # determine if responder is destination address if so exit

    if (srcKey == destAddr):
        sys.exit()


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
