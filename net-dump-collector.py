#!/bin/python

#   script that collects network dumps when a condition is met from the logs
#   functions that the script has to perform:
#   1 - take continuous network dumps from a vmnic to a file
#   2 - rotate that file and remove it after a while
#   3 - continuosuly monitor and parse a log file and search for a string
#   4 - if the string is found, then stop the captures and send a message





import subprocess
import sys
import re
import time



log = '/var/log/clomd.log'
netdumpcmd ='pktcap-uw --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 1 -o esxdir1.pcap'

# regex generated using http://txt2re.com/index-python.php3?s=Removing%2059523f9b-04ab-6a30-a574-54ab3a773d8e%20of%20type%20CdbObjectNode%20from%20CLOMDB&6&49&1&50&35&51&12&52&2&53&11&54&8

re1='Removing' # Word 1
re2='(\\s+)'    # White Space 1
re3='([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})'    # SQL GUID 1
re4='(\\s+)'    # White Space 2
re5='((?:[a-z][a-z]+))' # Word 2
re6='(\\s+)'    # White Space 3
re7='((?:[a-z][a-z]+))' # Word 3
re8='(\\s+)'    # White Space 4
re9='((?:[a-z][a-z]+))' # Word 4
re10='(\\s+)'   # White Space 5
re11='((?:[a-z][a-z]+))'        # Word 5
re12='(\\s+)'   # White Space 6
re13='CLOMDB'        # Word 6

# Regex Compilation that matches exactly a string like: "Removing 59523f9b-04ab-6a30-a574-54ab3a773d8e of type CdbObjectNode from CLOMDB"
# #2018-01-16T11:56:57.933Z 33787 Removing 59523f9b-04ab-6a30-a574-54ab3a773d8e of type CdbObjectNode from CLOMDB
rg = re.compile(re1+re2+re3+re4+re5+re6+re7+re8+re9+re10+re11+re12+re13,re.IGNORECASE|re.DOTALL)

capturedir0 = 'pktcap-uw --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 0 -o /tmp/esxdir0.pcap'
capturedir1 = 'pktcap-uw --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 1 -o /tmp/esxdir1.pcap'

# runDump()
# Function that starts the network dump

def runDump():

    try:
        retcodedir0 = subprocess.call(capturedir0, shell=True)
        retcodedir1 = subprocess.call(capturedir1, shell=True)

    except OSError as e:
            print >> sys.stderr, "Run Dump Execution failed:", e



# killDump()
# Function that kills the running packet capture

def killDump():

    try:
        cmd = "kill $(lsof |grep pktcap-uw | awk '{print $1}'| sort -u)"
        killPid = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        killOut = killPid.communicate()[0]
    except OSError as e:
         print >> sys.stderr, "Kill Dump Execution failed:", e



# checkSize()
# Function that returns the size of the output dump

def checkSize():

    try:
        cmd = "du /tmp/esxdir1.pcap | cut -f1"
        size = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output = size.communicate()[0]

    except OSError as e:
         print >> sys.stderr, "Check Size Execution failed:", e

    return int(output)



# scanLog()
# Function that scans a log file and return 0 if a match is found

def scanLog():

    try:
        textfile = open(log, 'r')
        filetext = textfile.read()
        textfile.close()
        if re.findall(rg, filetext):
            return 0
        else:
            return 1

    except OSError as e:
         print >> sys.stderr, "Check Size Execution failed:", e

# logESX()
# Function that marks the ESXi logs with a message

def logESX():
    try:
        retcode = subprocess.call("esxcli system syslog mark" + " -s 'START_HERE'", shell=True)
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        else:
            print >> sys.stderr, "Child returned", retcode
    except OSError as e:
        print >> sys.stderr, "logESX Execution failed:", e

# cleanLog()
# Function that removes the Network Dump

def cleanLog():

    try:
        retcode = subprocess.call("rm" + " /tmp/esxdir[0-1].pcap", shell=True)
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        else:
            print >> sys.stderr, "Child returned", retcode
    except OSError as e:
        print >> sys.stderr, "cleanLog Execution failed:", e

# vmSupport()
# Generates a vm-support log bundle

def vmSupport():

    try:
        bundle =  subprocess.call("vm-support", shell=True)
    except OSError as e:
        print >> sys.stderr, "vm-support Execution failed:", e




# main()
# This is the main program logic based on all the helper functions that will deal with the network capture


def main():

# we start first the dump
    runDump()

    while True:
        curSize = checkSize()
        if curSize > 4 and scanLog() == 1: # test that the size is small and that we dont have a match so we can kill the dump/clean the log and start a new dump
            killDump()      # Kills the Dump
            cleanLog()      # Deletes the Captures
            runDump()       # rerun the Dump
        elif curSize > 4 and scanLog() == 0:
            logESX()        # Mark ESXi Logs when a string is found and stops the Dump.
            time.sleep(30)  # sleeps for 30 seconds before killing the dump
            print "Program Sleeping 30s ..."
            killDump()      # Kills the Dump after 30 seconds
            vmSupport()     # Generates a vm-support log bundle from ESXi
            exit()          # Exit the Python Scrip


    return 0




# Start program
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write('\nDetect: Interrupted\n')
        sys.exit(1)
    except Exception as err:
        log.error('Caused: %s', err)
        log.error("[ABNORMAL END]")
        sys.exit(1)
