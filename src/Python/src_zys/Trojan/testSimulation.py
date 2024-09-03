"""
testSimulation.py

Description: This file is meant to test an individual simulation of a given 
    virus in a given network. There are 6 different network shapes that you can
    choose from and 4 diffent viruses

Notes: You cannot run multiple viruses in one simulation
        For visualization, it is not recommend to use more than 15 nodes in a 
        network
"""

import simulateVirusSpread as sim
import displayVirusSpread as disp
import viruses
import Network as n
import fileMaker
import time

shapeMaker = {0:fileMaker.star, 1:fileMaker.tree, 2:fileMaker.ring, 
            3:fileMaker.line , 4:fileMaker.fullConnected, 5:fileMaker.mesh }
            
shapeName = {0:"star", 1:"tree", 2:"ring", 3:"line" , 4:"fullConnected", 5:"mesh" }

shapeFileName = {0:"star.txt", 1:"tree.txt", 2:"ring.txt", 3:"line.txt" ,
                4:"fullConnect.txt", 5:"mesh.txt" }

shapeOfNetwork = {0:disp.graphType.STAR, 1:disp.graphType.TREE, 2:disp.graphType.RING, 
    3:disp.graphType.LINE , 4:disp.graphType.ALL_CONNECTED, 5:disp.graphType.MESH }
    
virusDispatch = {0:viruses.Worm, 1:viruses.Trojan, 2:viruses.LogicBomb, 3:viruses.SuperVirus}

#Modify the varibles below to Change Simulation Types. IT is not recommend to do
# make the NETWORK_SIZE greater than 15
#=============================================================================
# 0 = WORM
# 1 = TROJAN
# 2 = LOGIC BOMB
# 3 = SUPER VIRUS
RUN_VIRUS = 0
# 0 = STAR
# 1 = TREE
# 2 = RING
# 3 = LINE
# 4 = FULLY CONNECTED
# 5 = MESH
NETWORK_SHAPE = 4
NETWORK_SIZE = 15
#=============================================================================

#Running the Simulation
shapeMaker[NETWORK_SHAPE](NETWORK_SIZE)
virus = virusDispatch[RUN_VIRUS]()
theNetwork = n.Network(shapeOfNetwork[NETWORK_SHAPE])
theNetwork.createnetwork(shapeFileName[NETWORK_SHAPE])
sim.runOnce(theNetwork, 1, virus)
time.sleep(1)       #allow the graph to stay on screen for 1 second