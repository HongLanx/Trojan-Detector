"""
testNetwork.py

Description: This file is meant to test if the Network class is correctly 
            creating the networks from the text files. It does this by 
            creating the files with a certain number of nodes and comparing it 
            to the number of nodes in the network.

Notes: Because a network cannot have less than 2 nodes, each network starts at
        2 nodes and increments by 1 until 100.
"""

import Network as net
from time import sleep
import fileMaker

# NONE = 0
# RING = 1
# STAR = 2
# MESH = 3
# ALL_CONNECTED = 4
# BUS = 5
# HYBRID = 6
# LINE = 7
# TREE = 8

# run 9 times for each network shape
for networkShape in range(1,9):
    maker = None
    fileName = None
    #create a network based on shape
    network = net.Network(networkShape)
    #assign approperiate file make and filename to maker and filename
    if(networkShape == 1):
        maker = fileMaker.ring
        fileName = "ring.txt"
    elif(networkShape == 2):
        maker = fileMaker.star
        fileName = "star.txt"
    elif(networkShape == 3):
        maker = fileMaker.mesh
        fileName = "mesh.txt"
    elif(networkShape == 4):
        maker = fileMaker.fullConnected
        fileName = "fullconnect.txt"
    elif(networkShape == 5):
        continue
    elif (networkShape == 6):
        continue
    elif (networkShape == 7):
        maker = fileMaker.line
        fileName = "line.txt"
    elif (networkShape == 8):
        maker = fileMaker.tree
        fileName = "tree.txt"
    else:
        print("Tests Failed, Invalid shape")
        break
    
    for x in range(2, 101, 1):
        #create each file and network
        maker(x)
        network.createnetwork(fileName)
        #check the number of nodes in the network and pass or fail the test
        if(len(network.nodes) == x):
            print("Test",str(x), "Passed")
        else:
            print("Test", str(x), "Failed")
            break
print("Network Tests Completed")