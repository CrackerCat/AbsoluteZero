import os
import threading
import time
from core.data import viewbag
from core.utils import tools
from core.handler import TCPhandler
from core.color import color
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement

fname = tools.GetStartupPath(__file__) + '\\configuration.xml'


def save():
    print '\n' + color.ReturnInfo('Saving current system configuration...')
    try:
        viewbag_node = Element('viewbag')
        system_node = SubElement(viewbag_node, 'system')
        port_list = TCPhandler.Helper.GetPrintablePorts()
        SubElement(system_node, 'CALLBACK_IP', name=viewbag.CALLBACK_IP)
        SubElement(system_node, 'BUFFER_SIZE', name=str(viewbag.BUFFER_SIZE))
        SubElement(system_node, 'PORT_LIST', name=port_list)
        SubElement(system_node, 'MAX_CONN', name=str(viewbag.MAX_CONN))
        SubElement(system_node, 'MESSAGE_LENGTH_SHOW', name=str(viewbag.MESSAGE_LENGTH_SHOW))
        SubElement(system_node, 'ENVIRONMENT_FOLDER', name=viewbag.ENVIRONMENT_FOLDER)
        SubElement(system_node, 'NOTIFY_CONNECTION', name=str(viewbag.NOTIFY_CONNECTION))
        SubElement(system_node, 'AUTOSTART_TCP', name=str(viewbag.AUTOSTART_TCP))
        output_file = open(fname, 'w')
        print color.ReturnInfo('Writing to "configuration.xml"...')
        output_file.write('<?xml version="1.0"?>')
        output_file.write(ElementTree.tostring(viewbag_node))
        output_file.close()
        print color.ReturnSuccess('Saved to -> "%s"' % fname)
    except Exception, e:
        print color.ReturnError('Error saving configuration: %s' % str(e))
    print ''


def remove():
    try:
        print color.ReturnInfo('Removing current configuration...')
        os.remove(fname)
        print color.ReturnSuccess('Configuration removed successfully.')
    except Exception, e:
        print color.ReturnError('Error removing configuration: %s' % str(e))


def load():
    try:
        if os.path.isfile(fname):
            print color.ReturnInfo('Loading configuration file...')
            counter = 0
            document = ElementTree.parse(fname)
            for setting in document.findall('system/'):
                if counter == 0:
                    viewbag.CALLBACK_IP = setting.attrib['name']
                elif counter == 1:
                    viewbag.BUFFER_SIZE = int(setting.attrib['name'])
                elif counter == 2:
                    TCPhandler.Helper.InitializePorts(setting.attrib['name'])
                elif counter == 3:
                    viewbag.MAX_CONN = int(setting.attrib['name'])
                elif counter == 4:
                    if setting.attrib['name'] == 'True':
                        viewbag.MESSAGE_LENGTH_SHOW = True
                    else:
                        viewbag.MESSAGE_LENGTH_SHOW = False
                elif counter == 5:
                    viewbag.ENVIRONMENT_FOLDER = setting.attrib['name']
                elif counter == 6:
                    if setting.attrib['name'] == 'True':
                        viewbag.NOTIFY_CONNECTION = True
                    else:
                        viewbag.NOTIFY_CONNECTION = False
                elif counter == 7:
                    if setting.attrib['name'] == 'True':
                        viewbag.AUTOSTART_TCP = True
                        if not viewbag.SERVER_STATUS:
                            if not viewbag.PORT_LIST:
                                print color.ReturnError('Error: port list is empty.')
                            elif not viewbag.CALLBACK_IP:
                                print color.ReturnError('Error: callback ip is not defined.')
                            else:
                                print color.ReturnInfo('Started Reverse TCP Handler on %s:%s' % (
                                    viewbag.CALLBACK_IP, TCPhandler.Helper.GetPrintablePorts()))

                                thread = threading.Thread(target=TCPhandler.Helper.StartTcpHandler)
                                thread.daemon = True
                                thread.start()
                                viewbag.SERVER_STATUS = True
                                time.sleep(1)
                        else:
                            print color.ReturnError('Server is already online.')
                    else:
                        viewbag.AUTOSTART_TCP = False
                counter += 1
            print color.ReturnSuccess('Configuration file loaded.\n')
    except Exception, e:
        print color.ReturnError('Error parsing the configuration: %s' % str(e))
