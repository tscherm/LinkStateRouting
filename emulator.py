import argparse
import sys
import socket
import traceback
import ipaddress
from datetime import datetime
import pickle
import copy

parser = argparse.ArgumentParser(description="Link State Routing Emulator")

parser.add_argument("-p", "--port", type=int, required=True, dest="port")
parser.add_argument("-f", "--filename", type=str, required=True, dest="fileName")

args = parser.parse_args()

# check port numbers
if 2049 > args.port or args.port > 65536:
    print("Sender port out of range.")
    sys.exit()
if 2049 > args.port or args.port > 65536:
    print("Requester port out of range.")
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
forwardingTable = dict() # {dest: (nextHop, dist)}

nodesLocationDict = dict() # keep ordered list of destinations (excluding self)
largestSeqNo = list() # largest sequence number for each node

neighborsLocationDict = dict() # doctionary of the locations of 
latestTimestamp = list() # last time stamp a HelloMessage was recieved (from neighbors)
isUp = list() # list of whether neighbors are up or down

forwardingTable = list() 

helloInterval = 1
dropInterval = 2.5
linkInterval = 1

isListening = True

# hello packet format: type 1B, srcIP 4B, srcPort 2B
# link state packet format: type 1B, srcIP 4B, srcPort 2B, seqNo 4B, TTL 4B, len 4B, data
# route trace packet format: type 1B, srcIP 4B, srcPort 2B, destIP 4B, destPort 2B, TTL 4b

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
def handlePacket(pack, time):
    global neighborsLocationDict
    global latestTimestamp
    global isUp
    global topology
    global topologyRef

    pType = pack[0] # 'H' = helloMessage, 'L' = linkeStateMessage, 'T' = routetrace

    if pType < 4: # network traffic
        return (pType, False)

    # get sender key
    srcIP = socket.ntohl(int.from_bytes(pack[1:5], 'big'))
    srcPort = socket.ntohs(int.from_bytes(pack[5:7], 'big'))
    senderKey = (ipaddress.ip_address(srcIP), int(srcPort))


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
        seqNo = socket.ntohl(int.from_bytes(pack[7:11], 'big'))
        tTL = socket.ntohl(int.from_bytes(pack[11:15], 'big'))
        length = socket.ntohl(int.from_bytes(pack[15:19], 'big'))

        # check if node exists
        if senderKey in nodesLocationDict.keys():
            # check if sequence number is new and update
            if largestSeqNo[nodesLocationDict[senderKey]] >= seqNo:
                return (pType, False) # seqNo was old
            largestSeqNo[nodesLocationDict[senderKey]] = seqNo

            # check topology
            newDict = pickle.loads(pack[19:19 + length])

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

    if pType == 84: # route trace packet
        return (pType, False)

    return (None, False) # wrong packet

# ipmlements Djikstra's to update forwarding table using topology
def updateForwardingTable():
    pass

def createroutes():
    # check for packet
    while isListening:
        try:
            # try to recieve packet and handle it
            data, addr = recSoc.recvfrom(4096)
            handled = handlePacket(data, datetime.now())

            # check if forwarding table needs to be updated
            if handled[1]:
                updateForwardingTable()

            forwardpacket(data, addr)

        except BlockingIOError:
            pass # skip down to check intervals
        
    
        # Djikstras

        
    pass

def forwardpacket(data, addr):
    # check packet type and what to do with it
    # reliable flooding
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