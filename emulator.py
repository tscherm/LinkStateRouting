import argparse
import sys
import socket
import traceback
import ipaddress
from datetime import datetime, timedelta
import pickle
import copy
import bisect

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
hostKey = (ipaddress.ip_address(ipAddr), int(args.port))

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
isUp = list() # list of whether nodes are up or down

neighborsLocationDict = dict() # doctionary of the locations of 
latestTimestamp = list() # last time stamp a HelloMessage was recieved (from neighbors)

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
    global isUp

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
                isUp.append(True)

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
            oldTime = latestTimestamp[neighborsLocationDict[senderKey]][1]
            if oldTime < time:
                latestTimestamp[neighborsLocationDict[senderKey]] = (senderKey, time)

            # make this link active and update topology if needed
            if not isUp[nodesLocationDict[senderKey]]:
                isUp[nodesLocationDict[senderKey]] = True
                # I assume no link distance data is sent over helloMessage
                # and it is assumed to be the same as the txt file described
                addNode(senderKey)
                return (pType, True)
            else:
                return (pType, False) # topology wasn't changed even if time was
        else:
            # add new neighbor
            neighborsLocationDict[senderKey] = len(latestTimestamp)
            latestTimestamp.append((senderKey, time))
            # add new node
            nodesLocationDict[senderKey] = len(largestSeqNo)
            largestSeqNo.append((senderKey, 0))
            isUp.append(True)
            return (pType, True)
        

    if pType == 76: # link state message

        # get sequence number
        seqNo = socket.ntohl(int.from_bytes(pack[13:17], 'big'))
        length = socket.ntohl(int.from_bytes(pack[21:25], 'big'))

        # check if node exists
        if senderKey in nodesLocationDict.keys():
            # check if sequence number is new and update
            if largestSeqNo[nodesLocationDict[senderKey]][1] >= seqNo:
                return (pType, False) # seqNo was old
            largestSeqNo[nodesLocationDict[senderKey]] = (senderKey, seqNo)

            # check topology
            newDict = pickle.loads(pack[25:25 + length])

            # find what nodes to add and what noes to remove
            toAdd = list()
            toRemove = list()
            changeMade = False

            # check if the node is up if not add it
            if not isUp[nodesLocationDict[senderKey]]:
                toAdd.append(senderKey)
                isUp[nodesLocationDict[senderKey]] = True
                changeMade = True
            
            # update new topology
            # check what differences there are

            for link in topologyRef[senderKey]:
                oldDist = topology[senderKey][link]
                newDist = newDict[link]

                # check if this link is newly reachable
                if oldDist >= sys.maxsize / 4 and newDist < sys.maxsize / 4:
                    toAdd.append(link)
                    isUp[nodesLocationDict[link]] = True
                    changeMade = True

                # check if this link is newly unreachable
                if newDist >= sys.maxsize / 4 and oldDist < sys.maxsize / 4:
                    toRemove.append(link)
                    isUp[nodesLocationDict[link]] = False
                    changeMade = True

            # add and remove values as needed
            for node in toAdd:
                addNode(node)

            for node in toRemove:
                removeNode(node)
            
            if changeMade:
                return (pType, True)
            else:
                return (pType, False)
        else:
            # add new node
            nodesLocationDict[senderKey] = len(largestSeqNo)
            largestSeqNo.append((senderKey, seqNo))
            return (pType, True)

    if pType == 79 or pType == 84: # route trace packet 'O' or 'T'
        return (pType, False)

    return (None, False) # wrong packet

# go through topology and add node
# update forward table and send link state
def addNode(node):
    global isUp
    # add node to dict
    for next in topology[node].keys():
        # make sure only nodes that are up are added back
        if not isUp[nodesLocationDict[next]]:
            continue
        topology[node][next] = topologyRef[node][next]
        topology[next][node] = topologyRef[next][node]

    # make node up if it is in neighors
    if node in neighborsLocationDict:
        isUp[nodesLocationDict[node]] = True

# go through topology and remove node
# update forward table and send link state
def removeNode(node):
    global isUp
    # remove node from dict
    for next in topology[node].keys():
        topology[node][next] = sys.maxsize
        topology[next][node] = sys.maxsize
    
    # make node not up if it is in neighors
    if node in neighborsLocationDict:
        isUp[nodesLocationDict[node]] = False



def createroutes():
    global lastHelloMessage
    global isUp
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
            if handled[0] == 76 or handled[0] == 78 or handled[0] == 79 or handled[0] == 84: # 'L', 'N', 'O', 'T'
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
        updateFTandLS = False
        for key in neighborsLocationDict.keys():
            i = nodesLocationDict[key]
            j = neighborsLocationDict[key]
            if latestTimestamp[j][1] < datetime.now() - downInterval and isUp[i]:
                updateFTandLS = True
                isUp[i] = False
                
                # update topology
                removeNode(key)
            
        if updateFTandLS:
            buildForwardTable()
            sendLinkState()
        
        # send LinkStateMessage
        if lastLinkStateMessage <= datetime.now() - linkInterval:
            sendLinkState()


# sends hello packet to all neighbors wether they are up or not
# hello packet format: type 1B, srcIP 4B, srcPort 2B
def sayHello():
    global lastHelloMessage

    # make packet
    pType = ord('H').to_bytes(1, 'big')
    srcIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
    srcPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
    packet = pType + srcIP + srcPort

    # send packets to all neighbors
    for destKey in neighborsLocationDict.keys():
        dest = (str(destKey[0]), destKey[1])
        sendSoc.sendto(packet, dest)

    lastHelloMessage = datetime.now()

# sends link state from this address
# link state packet format: type 1B, srcIP 4B, srcPort 2B, lastSenderIP 4B, lastSenderPort 2B, seqNo 4B, TTL 4B, len 4B, data
def sendLinkState():
    global lastSeqNoSent
    global lastLinkStateMessage
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

    lastLinkStateMessage = datetime.now()


def forwardpacket(data, addr, pType):
    # check packet type and what to do with it
    if pType == 78: # network traffic
        # send to next spot in forwarding table
        destIP = socket.ntohl(int.from_bytes(data[7:11], 'big'))
        destPort = socket.ntohs(int.from_bytes(data[11:13], 'big'))
        destKey = (ipaddress.ip_address(destIP), destPort)

        # find next hop and send
        nextHop = forwardingTable[neighborsLocationDict[destKey]][1]
        sendSoc.sendto(data, nextHop)

        return

    if pType == 76: # link state traffic # reliable flooding
        # check if sequence number is old
        srcIP = socket.ntohl(int.from_bytes(data[1:5], 'big'))
        srcPort = socket.ntohs(int.from_bytes(data[5:7], 'big'))
        srcKey = (ipaddress.ip_address(srcIP), srcPort)
        seqNo = socket.ntohl(int.from_bytes(data[13:17], 'big'))

        if largestSeqNo[nodesLocationDict[srcKey]][1] >= seqNo:
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
        srcKey = (ipaddress.ip_address(srcIP), srcPort)
        srcRTSend = (int(ipaddress.ip_address(srcIP)), srcPort)

        destIP = socket.ntohl(int.from_bytes(data[7:11], 'big'))
        destPort = socket.ntohs(int.from_bytes(data[11:13], 'big'))
        destKey = (ipaddress.ip_address(destIP), destPort)

        senderIP = socket.ntohl(int.from_bytes(data[13:17], 'big'))
        senderPort = socket.ntohs(int.from_bytes(data[17:19], 'big'))
        senderSend = (senderIP, senderPort)

        oldTTL = socket.ntohl(int.from_bytes(data[19:23], 'big'))

        # check if this is the destination address
        if destKey == hostKey:
            # check what type of packet this is
            if pType == 79: # 'O'
                # send packet to route trace application
                # no need to change packet
                nextHop = (str(ipaddress.ip_address(senderSend[0])), senderSend[1])
                sendSoc.sendto(data, nextHop)
                return
            else: # 'T'
                # check if packet should be sent back to trace immediately
                # send 'O' packet back to src
                if srcKey == destKey:
                    # just change packet type
                    forwardPacket = pType = ord('O').to_bytes(1, 'big') + data[1:]
                    nextHop = (str(ipaddress.ip_address(senderSend[0])), senderSend[1])
                    sendSoc.sendto(forwardPacket, nextHop)
                else:
                    sendRouteTraceReturn(srcRTSend, senderSend)
                return

        # check if TTL is 0
        if oldTTL == 0:
            # send time out message
            sendRouteTraceReturn(srcRTSend, senderSend)
            return # do not forward this

        # decrememnt TTL and make new packet
        first = data[:19]
        forwardPacket = first + socket.htonl(oldTTL - 1).to_bytes(4, 'big')

        # send packet to next destination
        nextHop = forwardingTable[neighborsLocationDict[destKey]][1]
        sendSoc.sendto(forwardPacket, nextHop)

        return


# route trace packet format: type 1B, srcIP 4B, srcPort 2B, destIP 4B, destPort 2B, senderIP 4B, senderPort 2B, TTL 4B
# switch oldSrc address to destination address
# put own address into src address
# keep sender port the same
def sendRouteTraceReturn(destAddr, senderAddr):
    # make new values
    pType = ord('O').to_bytes(1, 'big')
    srcIP = socket.htonl(int(hostKey[0])).to_bytes(4, 'big')
    srcPort = socket.htons(hostKey[1]).to_bytes(2, 'big')
    destIP = socket.htonl(destAddr[0]).to_bytes(4, 'big')
    destPort = socket.htons(destAddr[1]).to_bytes(2, 'big')
    senderIP = socket.htonl(senderAddr[0]).to_bytes(4, 'big')
    senderPort = socket.htons(senderAddr[1]).to_bytes(2, 'big')
    tTL = socket.htonl(19).to_bytes(4, 'big') # number of possibe hops
    rTPacket = pType + srcIP + srcPort + destIP + destPort + senderIP + senderPort + tTL

    # send packet to next destination
    destKey = (ipaddress.ip_address(destAddr[0]), destAddr[1])
    nextHop = forwardingTable[neighborsLocationDict[destKey]][1]
    sendSoc.sendto(rTPacket, nextHop)


def buildForwardTable():
    # make new lists
    nodesReached = dict() # {nodeKey: (distance, [p, a, t, h])}
    possiblePaths = list() # [(distance, [p, a, t, h]), ...]

    # initialize Djikstra's with neighbors
    for neighbor in topology[hostKey].keys():
        # do not add anything with infinite distance
        if topology[hostKey][neighbor] >= sys.maxsize / 4:
            continue
        
        bisect.insort(possiblePaths, (topology[hostKey][neighbor], [hostKey, neighbor]))
    nodesReached[hostKey] = (0, None)

    # do Djikstra's
    while len(nodesReached) < len(topology) and len(possiblePaths) > 0:
        # get next possible path
        pPath = possiblePaths.pop(0)
        destNode = pPath[1][-1]

        if destNode in nodesReached.keys(): # don't repeat nodes
            continue

        # add nodes to reached lists
        nodesReached[destNode] = pPath

        # add next nodes to possible paths
        for key in topology[destNode].keys():
            # do not add anything with infinite distance
            if topology[destNode][key] >= sys.maxsize / 4:
                continue
            nextDist = pPath[0] + topology[destNode][key]
            nextPath = copy.deepcopy(pPath[1])
            nextPath.append(key)

            bisect.insort(possiblePaths, (nextDist, nextPath))

    # make new forwarding table to be copied over old forwarding table
    newForwardingTable = list()
    nodesReached.pop(hostKey) # remove host value needed earlier

    for destKey in nodesReached.keys():
        nextHopK = nodesReached[destKey][1][1]
        nextHop = (str(nextHopK[0]), nextHopK[1])
        forwardingValue = (destKey, nextHop)
        newForwardingTable.append(forwardingValue)

    # copy new forwarding table over old forwarding table
    global forwardingTable
    forwardingTable = copy.deepcopy(newForwardingTable)

    # print topology and forwarding table every time it changes
    # since this is called every time it changes it is sufficient to print this here
    printTandFT()

def printTandFT():
    # print topology
    print("Topology:\n")

    for node in nodesLocationDict.keys():
        # make beginning of string and wether to print variable
        strToPrint = f"{str(node[0])},{node[1]}"
        toPrint = False

        for next in topology[node].keys():
            # do not add infinite values
            if topology[node][next] >= sys.maxsize / 4:
                continue

            toPrint = True
            strToPrint += f" {str(next[0])},{next[1]},{topology[node][next]}"

        if toPrint:
            print(strToPrint)

    print() # extra line for spacing

    # print Forwarding Table
    print("Forwarding Table:\n")
    
    for entry in forwardingTable:
        print(f"{str(entry[0][0])},{entry[0][1]} {entry[1][0]},{entry[1][1]}")

    print() # extra line for spacing

def cleanup():
    recSoc.close()
    sys.exit()

def main():
    readtopology()
    buildForwardTable()
    createroutes()
    cleanup()

if __name__ == '__main__':
    main()
