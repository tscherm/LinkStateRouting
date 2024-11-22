import argparse

parser = argparse.ArgumentParser(description="Network Emulator")

parser.add_argument("-a", "--routetrace_port", type=int, required=True, dest="rtPort")
parser.add_argument("-b", "--source_hostname", type=str, required=True, dest="srcHost")
parser.add_argument("-c", "--source_port", type=int, required=True, dest="srcPort")
parser.add_argument("-d", "--destination_hostname", type=int, required=True, dest="destHost")
parser.add_argument("-e", "--destination_port", type=int, required=True, dest="destPort")
parser.add_argument("-f", "--debug_option", type=int, required=True, dest="debug")

args = parser.parse_args()




# 
# type: ignore