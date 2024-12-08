import argparse
import sys
import socket
import traceback
import ipaddress
from datetime import datetime

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
topology = dict() # keep dictionary of immediate links between nodes
forwardingTable = dict() # {dest: (nextHop, dist)}
nodesLocationDict = dict() # keep ordered list of destinations (excluding self)
largestSeqNo = list() # largest sequence number for each node
latestTimestamp = list() # last time stamp a HelloMessage was recieved (from neighbors)
forwardingTable = list()

def readtopology():
    global topology
    global nodesLocationDict
    global largestSeqNo
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
    except:
        print(traceback.format_exc())

    # get neighbor time stamps
    for node in topology[hostKey].keys():
        latestTimestamp.append((node, time))


def createroutes():
    pass

def forwardpacket():
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