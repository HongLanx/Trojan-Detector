"""
testShape.py

Description: This file is meant to test if the shapes are being drawn correctly.
            It will draw a networks with sizes of 5 to 15 starting with line and
            ending with mesh network. It should be noted that each network is
            visible for 1 second after being diplayed to the screen.

Notes: In the first graph, it will draw a single red line that will remain
        throughout the rest of the graphs. This is because the display object
        is only meant to be used once per compliation.
"""

import displayVirusSpread as disp
import fileMaker as make
from time import sleep


for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.line(current)
    sleep(1) # Time in seconds.
    displayData.animationSteps.append([(1,2)])
    disp.LINE_GRAPH = disp.drawGraphFromFile('line.txt')
    displayData.typeOfGraph = disp.graphType.LINE
    disp.display(displayData)

for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.ring(current)
    sleep(1) # Time in seconds.
    displayData.animationSteps.append([(1,2)])
    disp.RING_GRAPH = disp.drawGraphFromFile('ring.txt')
    displayData.typeOfGraph = disp.graphType.RING
    disp.display(displayData)
    
for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.star(current)
    sleep(1)
    displayData.animationSteps.append([(1,2)])
    disp.STAR_GRAPH = disp.drawGraphFromFile('star.txt')
    displayData.typeOfGraph = disp.graphType.STAR
    disp.display(displayData)


for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.fullConnected(current)
    sleep(1) # Time in seconds.
    displayData.animationSteps.append([(1,2)])
    disp.ALL_CONNECTED_GRAPH = disp.drawGraphFromFile('fullconnect.txt')
    displayData.typeOfGraph = disp.graphType.ALL_CONNECTED
    disp.display(displayData)

for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.tree(current)
    sleep(1) # Time in seconds.
    displayData.animationSteps.append([(1,2)])
    disp.TREE_GRAPH = disp.drawGraphFromFile('tree.txt')
    displayData.typeOfGraph = disp.graphType.TREE
    disp.display(displayData)

for current in range(5,15):
    displayData = disp.dataToDisplay()
    make.mesh(current)
    sleep(1) # Time in seconds.
    displayData.animationSteps.append([(1,2)])
    disp.MESH_GRAPH = disp.drawGraphFromFile('mesh.txt')
    displayData.typeOfGraph = disp.graphType.MESH
    disp.display(displayData)
    
