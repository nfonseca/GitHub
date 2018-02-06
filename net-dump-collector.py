#!/bin/python

#   script that collects network dumps when a condition is met from the logs
#   functions that the script has to perform:
#   1 - take continuous network dumps from a vmnic to a file
#   2 - rotate that file and remove it after a while
#   3 - continuosuly monitor and parse a log file and search for a string
#   4 - if the string is found, then stop the captures and send a message

# variables



import subprocess
import sys


log = '/var/log/clomd.log'
netdumpcmd ='pktcap-uw --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 1 -o esxdir1.pcap'
regex = 'Removing.[a-z0-9]\{8\}-[a-z0-9]\{4\}-[a-z0-9]\{4\}-[a-z0-9]\{4\}-[a-z0-9]\{12\}.of\stype\sCdbObjectNode\sfrom\sCLOMDB'




# run the dump function
# work on the bloack that iniates captures and does the log rotation

# a try block must always have a except.

# function to capture the dump file
# some improvements needed:
# add a variable for the parameters like uplink etc

def runDump():

    try:
        retcode = subprocess.call("pktcap-uw" + " --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 1 -o /tmp/esxdir1.pcap &", shell=True)
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        else:
            print >> sys.stderr, "Child returned", retcode
    except OSError as e:
            print >> sys.stderr, "Run Dump Execution failed:", e



def killDump():

    try:
        cmd = "kill $(lsof |grep pktcap-uw |awk '{print $1}'| sort -u)"
        killPid = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        killOut = killPid.communicate()[0]
    except OSError as e:
         print >> sys.stderr, "Kill Dump Execution failed:", e



def checkSize():

    try:
        cmd = "du /tmp/esxdir1.pcap | cut -f1"
        size = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output = size.communicate()[0]

    #     if int(output) > 32768:
    #         print "File is bigger than 32MB"
    #         # we should kill the capture here and start a new dump ?
    #         # or have a function to kill the capture and all it here ?
    #         # does the check and kill should be done in the MAIN part we we stick to basic functions here ?
    #     else:
    #         print "File is less than 32MB"
    #
    except OSError as e:
         print >> sys.stderr, "Check Size Execution failed:", e

    return int(output)
# need a function to stop the capture





def main():

    curSize = checkSize()
    runDump()
    while True:
        curSize = checkSize()
        if curSize > 8:
            killDump()

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
