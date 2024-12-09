import argparse
import sys
import socket
import traceback
import ipaddress
from datetime import datetime, timedelta
import pickle
import copy

parser = argparse.ArgumentParser(description="Link State Routing Emulator")

parser.add_argument("-p", "--port", type=int, required=True, dest="port")
parser.add_argument("-f", "--filename", type=str, required=True, dest="fileName")

args = parser.parse_args()

# check port numbers
if 2049 > args.port or args.port > 65536:
    print("Port out of range.")
    sys.exit()

# open port (to listen on only?)
hostname = socket.gethostname()
ipAddr = socket.gethostbyname(hostname)

reqAddr = (ipAddr, args.port)
hostKey = (ipaddress.ipaddress(ipAddr), int(args.port))

# open socket
try:
    recSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recSoc.bind(reqAddr)
    recSoc.setblocking(0)
except:
    print("An error occured binding the socket")
    print(traceback.format_exc())
    sys.exit()

# socket to send from (not the same one)
sendSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# global variables
topology = dict() # dictionary of immediate links between nodes
topologyRef = dict() # keep dictionary of initial links between nodes

nodesLocationDict = dict() # keep ordered list of destinations (excluding self)
largestSeqNo = list() # largest sequence number for each node

neighborsLocationDict = dict() # doctionary of the locations of 
latestTimestamp = list() # last time stamp a HelloMessage was recieved (from neighbors)
isUp = list() # list of whether neighbors are up or down

forwardingTable = list() # [(dest, nextHop)]

helloInterval = timedelta(milliseconds=1000)
downInterval = timedelta(milliseconds=2100)
linkInterval = timedelta(milliseconds=4500)

lastHelloMessage = datetime.now() - timedelta(days=1)
lastLinkStateMessage = datetime.now() - timedelta(days=1)

isListening = True

lastSeqNoSent = 0
startTTL = 15

# hello packet format: type 1B, srcIP 4B, srcPort 2B
# link state packet format: type 1B, srcIP 4B, srcPort 2B, lastSenderIP 4B, lastSenderPort 2B, seqNo 4B, TTL 4B, len 4B, data
# route trace packet format: type 1B, srcIP 4B, srcPort 2B, destIP 4B, destPort 2B, senderIP 4B, senderPort 2B, TTL 4B

def readtopology():
    global topology
    global topologyRef
    global nodesLocationDict
    global largestSeqNo
    global neighborsLocationDict
    global latestTimestamp

    time = datetime.now()

    # read topology file
    try:
        with open(args.fileName, 'r') as topologyFile:
            lines = topologyFile.readlines()

            # iterate over lines in file and add nodes to topology
            for line in lines:
                nodes = line.split()
                linksToAdd = dict()

                # get link values 
                for i in range(1, len(nodes)):
                    nodeVals = nodes[i].split(',')
                    nodeKey = (ipaddress.ip_address(nodeVals[0]), int(nodeVals[1]))
                    linksToAdd[nodeKey] = int(nodeVals[2])

                # get dict key
                keyVals = nodes[0].split(',')
                key = (ipaddress.ip_address(keyVals[0]), int(keyVals[1]))

                # add value to dictionary
                topology[key] = linksToAdd

                # add to nodes dict and sequence number
                nodesLocationDict[key] = len(largestSeqNo)
                largestSeqNo.append((key, 0))

    except FileNotFoundError:
        print(f"File {args.fileName} not found")
        sys.exit()
    except:
        print(traceback.format_exc())
        sys.exit()

    # get neighbor time stamps
    for node in topology[hostKey].keys():
        neighborsLocationDict[node] = len(latestTimestamp)
        latestTimestamp.append((node, time))
        isUp.append(True)

    # make topologyRef
    topologyRef = copy.deepcopy(topology)

# checks type of packet
# updates tables if needed
# does NOT update forwarding table or send packets
# returns (type of packet, if topology change was made)
# if ('H', True) need to send new LinkStateMessage
def handlePacket(pack, time):
    global neighborsLocationDict
    global latestTimestamp
    global isUp
    global topology
    global topologyRef

    pType = pack[0] # 'H' = helloMessage, 'L' = linkeStateMessage, 'O' = time out, 'T' = routetrace

    if pType < 4: # network traffic
        return (78, False) # 78 = 'N' for network traffic

    # get sender key
    srcIP = socket.ntohl(int.from_bytes(pack[1:5], 'big'))
    srcPort = socket.ntohs(int.from_bytes(pack[5:7], 'big'))
    senderKey = (ipaddress.ip_address(srcIP), srcPort)


    if pType == 72: # helloMessage
        # check if node is neighbor already
        if senderKey in neighborsLocationDict.keys():
            # check if it is an old time update if it is not
            oldTime = latestTimestamp[neighborsLocationDict[senderKey]]
            if oldTime < time:
                latestTimestamp[neighborsLocationDict[senderKey]] = time

            # make this link active and update topology if needed
            if not isUp[neighborsLocationDict[senderKey]]:
                isUp[neighborsLocationDict[senderKey]] = True
                # I assume no link distance data is sent over helloMessage
                # and it is assumed to be the same as the txt file described
                # ??? Do i need to update the backwards sending topology[senderKey][hostKey] ???
                topology[hostKey][senderKey] = topologyRef[hostKey][senderKey]
                return (pType, True)
            else:
                return (pType, False) # topology wasn't changed even if time was
        else:
            # add new neighbor
            neighborsLocationDict[senderKey] = len(latestTimestamp)
            latestTimestamp.append((senderKey, time))
            isUp.append(True)
            return (pType, True)
        

    if pType == 76: # link state message
        # get sequence number
        seqNo = socket.ntohl(int.from_bytes(pack[13:17], 'big'))
        length = socket.ntohl(int.from_bytes(pack[21:25], 'big'))

        # check if node exists
        if senderKey in nodesLocationDict.keys():
            # check if sequence number is new and update
            if largestSeqNo[nodesLocationDict[senderKey]] >= seqNo:
                return (pType, False) # seqNo was old
            largestSeqNo[nodesLocationDict[senderKey]] = seqNo

            # check topology
            newDict = pickle.loads(pack[25:25 + length])

            # check if newDict is different from old dict
            if newDict == topology[senderKey]:
                return (pType, False) # most likely a timed packet
            # update new topology
            topology[senderKey] = newDict
            return (pType, True)
        else:
            # add new node
            nodesLocationDict[senderKey] = len(largestSeqNo)
            largestSeqNo.append((senderKey, seqNo))
            return (pType, True)

    if pType == 79 or pType == 84: # route trace packet 'O' or 'T'
        return (pType, False)

    return (None, False) # wrong packet


def createroutes():
    global lastHelloMessage
    # check for packet
    while isListening:
        try:
            # try to recieve packet and handle it
            data, addr = recSoc.recvfrom(4096)
            handled = handlePacket(data, datetime.now())

            if handled[0] == None:
                continue # miscleanous packet

            # check if forwarding table needs to be updated
            if handled[1]:
                buildForwardTable()

            # check if this recieved packet should be forwarded
            if handled[0] == 76 or handled[0] == 78 or handled[0] == 79 or handled[0] == 84: # 'N', 'L', 'O', 'T'
                forwardpacket(data, addr, handled[0])

            # check if a new link state message needs to be created
            if handled[0] == 72 and handled[1]:
                sendLinkState()

        except BlockingIOError:
            pass # skip down to check intervals
        except KeyboardInterrupt:
            sys.exit()
        except:
            print("Something went wrong when listening for or interacting with packet.")
            print(traceback.format_exc())
        
        # send helloMessage timed
        if lastHelloMessage <= datetime.now() - helloInterval:
            sayHello()
        
        # check for neighbors that have not sent helloMessage
        updateFT = False
        for key in neighborsLocationDict.keys():
            i = neighborsLocationDict[key]
            if latestTimestamp[i] < timedelta.now() - downInterval and isUp[i]:
                updateFT = True
                isUp[i] = False
            
        if updateFT:
            buildForwardTable()
        
        # send LinkStateMessage
        if lastLinkStateMessage <= datetime.now() - linkInterval:
            sendLinkState()


# sends hello packet to all neighbors wether they are up or not
# hello packet format: type 1B, srcIP 4B, srcPort 2B
def sayHello():
    # make packet
    pType = ord('H').to_bytes(1, 'big')
    srcIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
    srcPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
    packet = pType + srcIP + srcPort

    # send packets to all neighbors
    for destKey in neighborsLocationDict.keys():
        dest = (str(destKey[0]), destKey[1])
        sendSoc.sendto(packet, dest)

# sends link state from this address
# link state packet format: type 1B, srcIP 4B, srcPort 2B, lastSenderIP 4B, lastSenderPort 2B, seqNo 4B, TTL 4B, len 4B, data
def sendLinkState():
    global lastSeqNoSent
    lastSeqNoSent += 1
    # serialize data
    linkStateToSend = pickle.dumps(topology[hostKey])
    # make packet
    pType = ord('L').to_bytes(1, 'big')
    srcIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
    srcPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
    lastSenderIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
    lastSenderPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
    seqNo = socket.htonl(lastSeqNoSent).to_bytes(4, 'big')
    tTL = socket.htonl(startTTL).to_bytes(4, 'big')
    length = socket.htonl(len(linkStateToSend)).to_bytes(4, 'big')
    packet = pType + srcIP + srcPort + lastSenderIP + lastSenderPort + seqNo + tTL + length + linkStateToSend

    # send packets to all neighbors
    for destKey in neighborsLocationDict.keys():
        dest = (str(destKey[0]), destKey[1])
        sendSoc.sendto(packet, dest)


def forwardpacket(data, addr, pType):
    # check packet type and what to do with it
    if pType == 76: # network traffic
        pass # send to next spot in forwarding table

    if pType == 78: # link state traffic # reliable flooding
        # check if sequence number is old
        srcIP = socket.ntohl(int.from_bytes(data[1:5], 'big'))
        srcPort = socket.ntohs(int.from_bytes(data[5:7], 'big'))
        srcKey = (ipaddress.ip_address(srcIP), srcPort)
        seqNo = socket.ntohl(int.from_bytes(data[13:17], 'big'))

        if largestSeqNo[nodesLocationDict[srcKey]] >= seqNo:
            return # seqNo was old

        # check if TTL is 0
        oldTTL = socket.ntohl(int.from_bytes(data[17:21], 'big'))
        if oldTTL == 0:
            # do I send time out packet here?
            return # do not forward this
        
        # get old values
        lastSenderIP = socket.ntohl(int.from_bytes(data[7:11], 'big'))
        lastSenderPort = socket.ntohs(int.from_bytes(data[11:13], 'big'))
        lastSender = (ipaddress.ip_address(lastSenderIP), lastSenderPort)

        first = data[0:7]
        second = data[13:17]
        third = data[21:]

        # make new values
        newSenderIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
        newSenderPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
        newTTL = socket.htonl(oldTTL - 1).to_bytes(4, 'big')

        # make new packet to forward
        forwardPacket = first + newSenderIP + newSenderPort + second + newTTL + third

        # forward packet to all neighbors except last sender
        # send packets to all neighbors
        for destKey in neighborsLocationDict.keys():
            if destKey == lastSender:
                continue # skip who sent the packet

            dest = (str(destKey[0]), destKey[1])
            sendSoc.sendto(forwardPacket, dest)
        
        return # packets sent to neighbors


    if pType == 79 or pType == 84: # routetrace traffic 'O', 'T'
        # route trace packet format: type 1B, srcIP 4B, srcPort 2B, destIP 4B, destPort 2B, senderIP 4B, senderPort 2B, TTL 4B

        # get destination and source addresses
        srcIP = socket.ntohl(int.from_bytes(data[1:5], 'big'))
        srcPort = socket.ntohs(int.from_bytes(data[5:7], 'big'))
        srcSend = (str(ipaddress.ip_address(srcIP)), srcPort)

        destIP = socket.ntohl(int.from_bytes(data[7:11], 'big'))
        destPort = socket.ntohs(int.from_bytes(data[11:13], 'big'))
        destKey = (ipaddress.ip_address(destIP), destPort)

        senderIP = socket.ntohl(int.from_bytes(data[13:17], 'big'))
        senderPort = socket.ntohs(int.from_bytes(data[17:19], 'big'))
        senderSend = (senderIP, senderPort)

        # check if TTL is 0
        oldTTL = socket.ntohl(int.from_bytes(data[17:21], 'big'))
        if oldTTL == 0:
            sendRouteTraceTimeOut(srcSend, senderSend)
            return # do not forward this

        # decrememnt TTL and make new packet
        first = data[:19]
        oldTTL = socket.ntohl(int.from_bytes(data[19:23], 'big'))
        forwardPacket = first + socket.htonl(oldTTL - 1).to_bytes(4, 'big')

        # check if this is the destination address
        if destKey == hostKey:
            # check what type of packet this is
            if pType == 79: # 'O'
                # send packet to route trace application
                nextHop = (str(ipaddress.ip_address(senderSend[0])), senderSend[1])
                sendSoc.sendto(forwardPacket, nextHop)
            else: # 'T'
                # send 'O' packet back to src
                sendRouteTraceTimeOut(srcSend, senderSend)


        # send packet to next destination
        nextHop = forwardingTable[neighborsLocationDict[destKey]][1]
        sendSoc.sendto(forwardPacket, nextHop)



def sendRouteTraceTimeOut(destAddr, senderAddr):
    pass

def buildForwardTable():
    pass


def cleanup():
    recSoc.close()
    sys.exit()

def main():
    readtopology()
    cleanup()

if __name__ == '__main__':
    main()