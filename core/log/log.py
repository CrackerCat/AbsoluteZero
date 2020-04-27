import os
from time import strftime
from datetime import datetime

fname = ''


def InitializeLogs():
    global fname
    try:
        if not os.path.exists(os.path.dirname(os.path.realpath(__file__)) + '\logs'):
            os.makedirs(os.path.dirname(os.path.realpath(__file__)) + '\logs')
    except Exception, e:
        pass
    fname = os.path.dirname(os.path.realpath(__file__)) + '\logs\\' + datetime.now().strftime("%Y%m%d_%H_%M_%S") + ".txt"


def doLog(action):
    try:
        f = open(fname, "a")
        f.write(datetime.now().strftime("[%H:%M:%S %d-%m-%Y] ") + action + '\n')
        f.close()
    except Exception, e:
        print '[-] Critical: Log error -> "%s"' % str(e)
