import argparse
import sys
import socket
import traceback
import ipaddress

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
topology = dict()

def readtopology():
    global topology
    topology = dict()

    # read topology file
    try:
        with open(args.fileName, 'r') as topologyFile:
            lines = topologyFile.readlines()

            # iterate over lines in file and add nodes to topology
            for line in lines:
                nodes = line.split()
                linksToAdd = list()

                # get link values 
                for i in range(1, len(nodes)):
                    nodeVals = nodes[i].split(',')
                    node = (ipaddress.ip_address(nodeVals[0]), int(nodeVals[1]), int(nodeVals[2]))
                    linksToAdd.append(node)

                # get dict key
                keyVals = nodes[0].split(',')
                key = (ipaddress.ip_address(keyVals[0]), int(keyVals[1]))

                # add value to dictionary
                topology[key] = linksToAdd

    except FileNotFoundError:
        print(f"File {args.fileName} not found")
    except:
        print(traceback.format_exc())


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
    global topology
    print(topology)
    cleanup()

if __name__ == '__main__':
    main()