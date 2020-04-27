from core.color import color
from core.color import header
from core.config import config
from core.console import console
from core.config import xmllib
from core.log import log
from core.handler import mshta


def printBanner():
    color.ClearConsole()
    print header.Banner(config.VERSION)


def loadConfiguration():
    xmllib.load()


def loadLogs():
    log.InitializeLogs()


def loadMSHTA():
    mshta.serve()


if __name__ == '__main__':
    printBanner()
    loadLogs()
    loadConfiguration()
    loadMSHTA()
    console.CLI.console()
