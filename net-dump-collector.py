#!/bin/python

#   script that collects network dumps when a condition is met from the logs
#   functions that the script has to perform:
#   1 - take continuous network dumps from a vmnic to a file
#   2 - rotate that file and remove it after a while
#   3 - continuosuly monitor and parse a log file and search for a string
#   4 - if the string is found, then stop the captures and send a message

