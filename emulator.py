import argparse
import sys
import socket
from datetime import datetime, timedelta
import traceback
import logging
import random
import ipaddress

parser = argparse.ArgumentParser(description="Network Emulator")

parser.add_argument("-p", "--port", type=int, required=True, dest="port")
parser.add_argument("-f", "--filename", type=str, required=True, dest="fileName")
parser.add_argument("-q", "--queue_size", type=int, required=True, dest="queueSize")
parser.add_argument("-l", "--log", type=str, required=True, dest="logName")

args = parser.parse_args()

# configure logging
try:
    logging.basicConfig(filename=args.logName, encoding='utf-8', level=logging.DEBUG)
except:
    print("An error occured while trying to configure logging.")
    print(traceback.format_exc())
    sys.exit()

# check port numbers
if 2049 > args.port or args.port > 65536:
    logging.critical("Sender port out of range.")
    sys.exit()
if 2049 > args.port or args.port > 65536:
    logging.critical("Requester port out of range.")
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
    logging.critical("An error occured binding the socket")
    logging.critical(traceback.format_exc())
    sys.exit()

# socket to send from (not the same one)
sendSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# these lists will have (packet, (destIP, destSoc), timeToSend, nextHop)
queue = [list(), list(), list()]

# variable for determining if emulator should keep listening for packets
isListening = True

# set up random
random.seed(9)

# function to read the forwarding table
def readTracker():
    # create dictionary with file names
    global table
    table = dict()

    # first pass to get size for arrays of tuples of data
    with open(args.fileName, 'r') as ftable:
        lines = ftable.readlines()
        for line in lines:
            vals = line.split()

            # check if it is the right emulator
            if vals[0] != hostname or int(vals[1]) != args.port:
                continue

            # check if the value exists in the dictionary
            destKey = (ipaddress.ip_address(socket.gethostbyname(vals[2])), int(vals[3]))
            if table.get(destKey) is None:
                table[destKey] = list()
            # add string values to array
            table[destKey].append(((ipaddress.ip_address(socket.gethostbyname(vals[4])), int(vals[5])), int(vals[6]), int(vals[7]) / 100))

# write logs
def logPacket(pack, recAddr, destAddr, reason):

    logging.info(f"Packet dropped at {datetime.now()} because {reason}.")

    if destAddr is None:
        logging.info(f"Recieved from: {recAddr}\n")
    else:
        logging.info(f"Recieved from: {recAddr}\nTo be sent to: {destAddr}\n")

    logging.info(f"---------\n{pack}\n---------\n")

# queue the packet and if possible
# steps 2 & 3
# return 1 if packet is added to queue
# return 0 if the packet had to be dropped
# return -1 if there is an error
def queuePacket(pack, addr, time):
    # check if it is in the forwarding table
    destIP = socket.ntohl(int.from_bytes(pack[7:11], 'big'))
    destPort = socket.ntohs(int.from_bytes(pack[11:13], 'big'))
    destKey = (ipaddress.ip_address(destIP), destPort)


    global table
    tableEntry = table.get(destKey)

    if tableEntry is None:
        # drop (simply don't add to queue) and log
        logPacket(pack, addr, None, "destination is not in forwarding table")
        return 0

    tableEnt = tableEntry[0]

    # check priority of packet
    priority = pack[0] - 1

    if priority > 2 or priority < 0:
        logPacket(pack, addr, None, "priority was outside of 1, 2, or 3")
        return -1

    # check if you can add it
    if len(queue[priority]) < args.queueSize or pack[17] == 'R' or pack[17] == 'E':
        # calculate time to send
        tts = time + timedelta(milliseconds=tableEnt[1])

        # add to queue and return (packet, timeToSend, nextHop, lossProb)
        queue[priority].append((pack, tableEnt[0], tts, tableEnt[2]))
        return 1
    else:
        # drop packet (don't add it to queue) and log it
        logPacket(pack, addr, f"{tableEnt[0]}", "the queue is full")
        return 0
    
    
# look at queue and find a packet to send if one is available
# steps 4 - 7
# return 1 if a packet is sent
# return 0 if no packet is in queue or if a packet is being waited on
# return -1 if there is an error
def sendPacket():

    for q in queue:
        # check if there are packets in this queue
        if len(q) <= 0:
            continue

        toSend = q[0]

        # check if packet can be sent
        if toSend[2] < datetime.now():
            # try to send packet
            try:
                if random.random() >= toSend[3]:
                    recSoc.sendto(toSend[0], (str(toSend[1][0]), toSend[1][1]))
                else:
                    logPacket(toSend[0], "N/A", toSend[1], "of chance")
                # take packet off queue
                q.pop(0)
                return 1
            except:
                logging.error(f"Something went wrong when sending packet to {toSend[1][0]}:{toSend[1][1]}.")
                logging.error(traceback.format_exc())
                return -1
        else:
            # waiting on packet
            return 0
    
    # no packets in queue
    return 0
    

# wait for packets
# step 1 and controls other steps
def getPackets():
    while isListening:
        try:
            # try to recieve packet and handle it
            data, addr = recSoc.recvfrom(4096)
            queuePacket(data, addr, datetime.now())
        except BlockingIOError:
            pass # skip down to sendPacket()
        except KeyboardInterrupt:
            sys.exit()
        except:
            logging.error("Something went wrong when listening for packet.")
            logging.error(traceback.format_exc())

        # send packet from queue
        sendPacket()


def cleanup():
    recSoc.close()
    sys.exit()

def main():
    readTracker()
    getPackets()
    cleanup()


if __name__ == '__main__':
    main()
