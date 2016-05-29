#!/usr/bin/env python

# probeJam.py
# who? Steffen 'SteffnJ' Johansen
# when? 2016
# what?
#  
#
#

import logging #This and next line is to get scapy to shut up
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from signal import SIGINT, signal
from sys import exit#, argv
import re
import argparse

VERSION = "0.1"

# colors
W  = '\033[0m'  # white
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

def argumentTreater():
    # Create the parser object
    parser = argparse.ArgumentParser(description = "Jam and sniff"\
        + " some targets")

    # Providing the interface is not optional!
    parser.add_argument("interface",
                        type=str,
                        help = "target interface, in monitoring mode."\
                            + "\n\nExample: probeJam.py wlan0mon")
    args = parser.parse_args()

    # Returns all the arguments
    return parser.parse_args()


def main():
    args = argumentTreater()
    # Iterate over all args and define variables/options
'''
    if (verbose):
        printVerboseDetails()
    print W+"probeJam"
    global requests
    requests = []
    sniffed = sniff(iface=interface, prn = myFuckingsFilter)
    '''

def printVerboseDetails():
    print W
    print "probeJam.py"
    print "Version:%s"
    print "Created by SteffnJ"
    print "Thanks for using probeJam."

# Ugly regex that can be cleaned up
def myFuckingsFilter(packet):
    if (packet.haslayer(Dot11ProbeReq)):
        tmpString = packet.summary()
        ssid = re.sub("^.*/ SSID='", "", tmpString)
        ssid = re.sub("' /.*", "", ssid)
        tmpString = re.sub("^.*Management 4L ", "", tmpString)
        tmpString = re.sub(" / Dot11ProbeReq.*", "", tmpString)
        tmpString = re.sub(" > ff:ff:ff:ff:ff.*", "", tmpString)
        packetString = "Probe request:\t"
        packetString += tmpString
        packetString += "\t\t\t\tSSID: "
        packetString += ssid
        if (requests.count(packetString) == 0):  
            requests.append(packetString)
            print C+packetString
        
    elif (packet.haslayer(Dot11ProbeResp)):
        tmpString = packet.summary()
        ssid = re.sub("^.*/ SSID='", "", tmpString)
        ssid = re.sub("' /.*", "", ssid)
        tmpString = re.sub("^.*Management 5L ", "", tmpString)
        tmpString = re.sub(" / Dot11ProbeResp.*", "", tmpString)
        packetString = "Probe response:\t"
        packetString += tmpString
        packetString += "\t\tSSID: "
        packetString += ssid
        if (requests.count(packetString) == 0):  
            requests.append(packetString)
            print O+packetString
        

# Write the log to a file
def kill(signal, frame):
    if ('logFile' in globals()):
        print R+"\nWriting to file"
        f = open(logFile, "w")
        for line in requests:
            f.write(line + "\n")
        f.close()
    print R+"\nExiting"
    exit(1)


#def processArguments(parser):
#    parser.something9)
#TODO - TARGET parameter
if (__name__ == "__main__"):
    # Make sure that we can kill the program
    signal(SIGINT, kill)

    main()
'''

    #parser = argparse.ArgumentParser(description=
    #Sniffing and logging probe requests and responses
    #        
    #processArguments(parser)
    
    if (len(argv) < 2):
        print "Usage: probeRequestLogger.py -i iface [logFile]"
        exit(1)
    if (len(argv) == 3):
        # Provided logFile
        # You are pretty fucking stupid if you give a silly file
        # Remember, you are running as fucking root.......
        global logFile
        logFile = argv[2]
    iface = argv[1]
    main(iface)
    '''
