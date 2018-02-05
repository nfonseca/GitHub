#!/bin/python

#   script that collects network dumps when a condition is met from the logs
#   functions that the script has to perform:
#   1 - take continuous network dumps from a vmnic to a file
#   2 - rotate that file and remove it after a while
#   3 - continuosuly monitor and parse a log file and search for a string
#   4 - if the string is found, then stop the captures and send a message

# variables


# Python modules avaiable in ESXi
#
# root         23022 Oct 18 02:08 BaseHTTPServer.pyc
# -r--r--r--    1 root     root         29048 Oct 18 02:08 ConfigParser.pyc
# -r--r--r--    1 root     root         25128 Oct 18 02:08 Cookie.pyc
# -r--r--r--    1 root     root         11244 Oct 18 02:08 Queue.pyc
# -r--r--r--    1 root     root         27775 Oct 18 02:08 SocketServer.pyc
# -r--r--r--    1 root     root         12715 Oct 18 02:08 StringIO.pyc
# -r--r--r--    1 root     root         12636 Oct 18 02:08 UserDict.pyc
# -r--r--r--    1 root     root          8787 Oct 18 02:08 UserList.pyc
# -r--r--r--    1 root     root          4613 Oct 18 02:08 __future__.pyc
# -r--r--r--    1 root     root         32442 Oct 18 02:08 _abcoll.pyc
# -r--r--r--    1 root     root         16463 Oct 18 02:08 _strptime.pyc
# -r--r--r--    1 root     root         12798 Oct 18 02:08 _weakrefset.pyc
# -r--r--r--    1 root     root          6858 Oct 18 02:08 abc.pyc
# -r--r--r--    1 root     root         74426 Oct 18 02:08 argparse.pyc
# -r--r--r--    1 root     root         14498 Oct 18 02:08 ast.pyc
# -r--r--r--    1 root     root         10769 Oct 18 02:08 asynchat.pyc
# -r--r--r--    1 root     root         22671 Oct 18 02:08 asyncore.pyc
# -r--r--r--    1 root     root          2593 Oct 18 02:08 atexit.pyc
# -r--r--r--    1 root     root         12467 Oct 18 02:08 base64.pyc
# -r--r--r--    1 root     root         23066 Oct 18 02:08 bdb.pyc
# -r--r--r--    1 root     root          3396 Oct 18 02:08 bisect.pyc
# -r--r--r--    1 root     root          7218 Oct 18 02:08 cProfile.pyc
# -r--r--r--    1 root     root         33048 Oct 18 02:08 calendar.pyc
# -r--r--r--    1 root     root         37048 Oct 18 02:08 cgi.pyc
# -r--r--r--    1 root     root         13341 Oct 18 02:08 cgitb.pyc
# -r--r--r--    1 root     root         15404 Oct 18 02:08 cmd.pyc
# -r--r--r--    1 root     root         42955 Oct 18 02:08 codecs.pyc
# -r--r--r--    1 root     root         29543 Oct 18 02:08 collections.pyc
# -r--r--r--    1 root     root          2859 Oct 18 02:08 commands.pyc
# -r--r--r--    1 root     root          5234 Oct 18 02:08 contextlib.pyc
# -r--r--r--    1 root     root         13860 Oct 18 02:08 copy.pyc
# -r--r--r--    1 root     root          5809 Oct 18 02:08 copy_reg.pyc
# -r--r--r--    1 root     root         15394 Oct 18 02:08 csv.pyc
# -r--r--r--    1 root     root        188730 Oct 18 02:08 decimal.pyc
# -r--r--r--    1 root     root         65404 Oct 18 02:08 difflib.pyc
# -r--r--r--    1 root     root          6748 Oct 18 02:08 dis.pyc
# -r--r--r--    1 root     root         12594 Feb  4 12:36 esxclipy.pyc
# -r--r--r--    1 root     root         16450 Oct 18 02:08 fileinput.pyc
# -r--r--r--    1 root     root          4004 Oct 18 02:08 fnmatch.pyc
# -r--r--r--    1 root     root         39061 Oct 18 02:08 ftplib.pyc
# -r--r--r--    1 root     root          7746 Oct 18 02:08 functools.pyc
# -r--r--r--    1 root     root          4232 Oct 18 02:08 genericpath.pyc
# -r--r--r--    1 root     root          7304 Oct 18 02:08 getopt.pyc
# -r--r--r--    1 root     root          5199 Oct 18 02:08 getpass.pyc
# -r--r--r--    1 root     root         20948 Oct 18 02:08 gettext.pyc
# -r--r--r--    1 root     root          3463 Oct 18 02:08 glob.pyc
# -r--r--r--    1 root     root         17147 Oct 18 02:08 gzip.pyc
# -r--r--r--    1 root     root          7494 Oct 18 02:08 hashlib.pyc
# -r--r--r--    1 root     root         15734 Oct 18 02:08 heapq.pyc
# -r--r--r--    1 root     root         41522 Oct 18 02:08 httplib.pyc
# -r--r--r--    1 root     root         44530 Oct 18 02:08 inspect.pyc
# -r--r--r--    1 root     root          3914 Oct 18 02:08 io.pyc
# -r--r--r--    1 root     root          2235 Oct 18 02:08 keyword.pyc
# -r--r--r--    1 root     root          3662 Oct 18 02:08 linecache.pyc
# -r--r--r--    1 root     root         57134 Oct 18 02:08 locale.pyc
# -r--r--r--    1 root     root           443 Oct 18 02:08 md5.pyc
# -r--r--r--    1 root     root          9501 Oct 18 02:08 mimetools.pyc
# -r--r--r--    1 root     root         19666 Oct 18 02:08 mimetypes.pyc
# -r--r--r--    1 root     root           927 Oct 18 02:08 new.pyc
# -r--r--r--    1 root     root         18042 Oct 18 02:08 numbers.pyc
# -r--r--r--    1 root     root          6470 Oct 18 02:08 opcode.pyc
# -r--r--r--    1 root     root         62994 Oct 18 02:08 optparse.pyc
# -r--r--r--    1 root     root         29134 Oct 18 02:08 os.pyc
# -r--r--r--    1 root     root         51079 Oct 18 02:08 pdb.pyc
# -r--r--r--    1 root     root         45320 Oct 18 02:08 pickle.pyc
# -r--r--r--    1 root     root         10348 Oct 18 02:08 pipes.pyc
# -r--r--r--    1 root     root         21078 Oct 18 02:08 pkgutil.pyc
# -r--r--r--    1 root     root         40306 Oct 18 02:08 platform.pyc
# -r--r--r--    1 root     root         10065 Oct 18 02:08 popen2.pyc
# -r--r--r--    1 root     root         12926 Oct 18 02:08 posixpath.pyc
# -r--r--r--    1 root     root         11429 Oct 18 02:08 pprint.pyc
# -r--r--r--    1 root     root         18991 Oct 18 02:08 profile.pyc
# -r--r--r--    1 root     root         28913 Oct 18 02:08 pstats.pyc
# -r--r--r--    1 root     root          5616 Oct 18 02:08 pty.pyc
# -r--r--r--    1 root     root        105221 Oct 18 02:08 pydoc.pyc
# -r--r--r--    1 root     root          7289 Oct 18 02:08 quopri.pyc
# -r--r--r--    1 root     root         28365 Oct 18 02:08 random.pyc
# -r--r--r--    1 root     root         14778 Oct 18 02:08 re.pyc
# -r--r--r--    1 root     root          6490 Oct 18 02:08 repr.pyc
# -r--r--r--    1 root     root         35713 Oct 18 02:08 rfc822.pyc
# -r--r--r--    1 root     root         10103 Oct 18 02:08 runpy.pyc
# -r--r--r--    1 root     root         20535 Oct 18 02:08 sets.pyc
# -r--r--r--    1 root     root          8403 Oct 18 02:08 shlex.pyc
# -r--r--r--    1 root     root         20540 Oct 18 02:08 shutil.pyc
# -r--r--r--    1 root     root         20891 Oct 18 02:09 site.pyc
# -r--r--r--    1 root     root         18102 Oct 18 02:09 socket.pyc
# -r--r--r--    1 root     root         13534 Oct 18 02:09 sre_compile.pyc
# -r--r--r--    1 root     root          6520 Oct 18 02:09 sre_constants.pyc
# -r--r--r--    1 root     root         22357 Oct 18 02:09 sre_parse.pyc
# -r--r--r--    1 root     root         36576 Oct 18 02:09 ssl.pyc
# -r--r--r--    1 root     root          3401 Oct 18 02:09 stat.pyc
# -r--r--r--    1 root     root         23774 Oct 18 02:09 string.pyc
# -r--r--r--    1 root     root         15787 Oct 18 02:09 stringprep.pyc
# -r--r--r--    1 root     root           304 Oct 18 02:09 struct.pyc
# -r--r--r--    1 root     root         34956 Oct 18 02:09 subprocess.pyc
# -r--r--r--    1 root     root         87318 Oct 18 02:09 tarfile.pyc
# -r--r--r--    1 root     root         23854 Oct 18 02:09 tempfile.pyc
# -r--r--r--    1 root     root         12942 Oct 18 02:09 textwrap.pyc
# -r--r--r--    1 root     root         49197 Oct 18 02:09 threading.pyc
# -r--r--r--    1 root     root          4141 Oct 18 02:09 token.pyc
# -r--r--r--    1 root     root         15545 Oct 18 02:09 tokenize.pyc
# -r--r--r--    1 root     root         12979 Oct 18 02:09 traceback.pyc
# -r--r--r--    1 root     root          1512 Oct 18 02:09 tty.pyc
# -r--r--r--    1 root     root          3180 Oct 18 02:09 types.pyc
# -r--r--r--    1 root     root         57805 Oct 18 02:09 urllib.pyc
# -r--r--r--    1 root     root         55536 Oct 18 02:09 urllib2.pyc
# -r--r--r--    1 root     root         16207 Oct 18 02:09 urlparse.pyc
# -r--r--r--    1 root     root         25358 Oct 18 02:09 uuid.pyc
# -r--r--r--    1 root     root       1587352 Feb  5 12:57 vmkctl.pyc
# -r--r--r--    1 root     root         14980 Oct 18 02:09 warnings.pyc
# -r--r--r--    1 root     root         19289 Oct 18 02:09 weakref.pyc
# -r--r--r--    1 root     root         12632 Oct 18 02:09 xdrlib.pyc
# -r--r--r--    1 root     root         45515 Oct 18 02:09 zipfile.py


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




# Start program
if __name__ == "__main__":
    try:
        runDump()
    except KeyboardInterrupt:
        sys.stderr.write('\nDetect: Interrupted\n')
        sys.exit(1)
    except Exception as err:
        sys.stderr.write("[ABNORMAL END]")
        sys.exit(1)




