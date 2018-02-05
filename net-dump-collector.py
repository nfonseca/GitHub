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
        retcode = subprocess.call("pktcap-uw" + " --uplink vmnic1 --ip 224.2.3.4 --ip 224.1.2.3 --dir 1 -o /tmp/esxdir1.pcap", shell=True)
        if retcode < 0:
            print >> sys.stderr, "Child was terminated by signal", -retcode
        else:
            print >> sys.stderr, "Child returned", retcode
    except OSError as e:
            print >> sys.stderr, "Execution failed:", e

# need a function to rotate the logs

def rotateLogs():

    try:
        cmd = "du /tmp/esxdir1.pcap | cut -f1"
        size = subprocess.popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output = size.communicate()[0]
        print output

    except OSError as e:
        print >> sys.stderr, "Execution failed:", e

# need a function to stop the capture





# Start main program
if __name__ == "__main__":
    try:
        runDump()
        rotateLogs()

    except KeyboardInterrupt:
        sys.stderr.write('\nDetect: Interrupted\n')
        sys.exit(1)
    except Exception as err:
        sys.stderr.write("[ABNORMAL END]")
        sys.exit(1)




