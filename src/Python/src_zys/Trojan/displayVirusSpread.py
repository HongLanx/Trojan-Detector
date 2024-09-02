import numpy as N
import pygame
from enum import Enum
import sys

def drawGraphFromFile(fileName):
    retVal = []
    with open(fileName, 'r') as file:
        for line in file:
            if line[0] != '#':
                if line.find('\n') != -1:
                    retVal.append(line[:line.find('\n')].split("\t"))
                else:
                    retVal.append(line.split("\t"))
    return retVal

display_width  = 640
display_height = 480

ALL_CONNECTED_GRAPH = drawGraphFromFile('fullconnect.txt')
LINE_GRAPH          = drawGraphFromFile('line.txt')
MESH_GRAPH          = drawGraphFromFile('mesh.txt')
RING_GRAPH          = drawGraphFromFile('ring.txt')
STAR_GRAPH          = drawGraphFromFile('star.txt')
# HYBRID_GRAPH        = drawGraphFromFile('hybridGraph.txt')
TREE_GRAPH          = drawGraphFromFile('tree.txt')

computerImage = pygame.image.load("compImage.png")
computerImage = pygame.transform.scale(computerImage, (50, 50))

class treeNode:
    edges = None
    nodeNumber = None
    location = None
    def __init__(self, newNodeNumber):
        self.edges = []
        self.nodeNumber = newNodeNumber

def walkTree(tree, currentNode, startPosition, depth, retValRef):
    retValRef.append([int(currentNode), startPosition, depth])
    edgesToExplore = []
    for edge in tree[currentNode].edges:
        edgesToExplore.append(edge)
    edgesDone = 0

    for edge in edgesToExplore:
        edgesDone += 1
        walkTree(tree, edge, startPosition, depth + 100, retValRef)

def buildTreeComputerLocations(retVal):
    treeNodes = {}

    for edge in TREE_GRAPH:
        if edge[0] not in treeNodes:
            treeNodes[edge[0]] = treeNode(edge[0])
        if edge[1] not in treeNodes:
            treeNodes[edge[1]] = treeNode(edge[1])
        treeNodes[edge[0]].edges.append(edge[1])

    walkTree(treeNodes, '1', display_width/2, 100, retVal)
    # sort retVal by first element in each list
    retVal.sort(key=lambda x : x[0])

    for x in range(100, 500, 100):
        count = 0
        for line in retVal:
            if line[2] == x:
                count += 1
        repositionedValues = 0
        for line in retVal:
            if line[2] == x:
                repositionedValues += 1
                line[1] = ((display_width / (count + 1)) * repositionedValues)


    return retVal

def getComputerLocationsOnDisplay(typeOfGraph):
    retVal = [[0, -1, -1]]
    if typeOfGraph == graphType.STAR:
        centerOfFieldX = int(display_width/2)
        centerOfFieldY = int(display_height/2)

        numberOfNodes = N.amax(N.array(STAR_GRAPH).astype(int))
        retVal.append([1, centerOfFieldX, centerOfFieldY])
        for x in range(2, (numberOfNodes + 1)):
            retVal.append([x, \
            centerOfFieldX + ((display_height / 3) * N.sin((x - 2) * ((2 * N.pi) / (numberOfNodes-1)))), \
            centerOfFieldY - ((display_height / 3) * N.cos((x - 2) * ((2 * N.pi) / (numberOfNodes-1))))])
    elif typeOfGraph == graphType.RING:
        centerOfFieldX = int(display_width/2)
        centerOfFieldY = int(display_height/2)

        numberOfNodes = N.amax(N.array(RING_GRAPH).astype(int))
        for x in range(1, (numberOfNodes + 1)):
            retVal.append([x, \
            centerOfFieldX + ((display_height / 3) * N.sin((x - 2) * ((2 * N.pi) / numberOfNodes))), \
            centerOfFieldY - ((display_height / 3) * N.cos((x - 2) * ((2 * N.pi) / numberOfNodes)))])
    elif typeOfGraph == graphType.MESH:
        centerOfFieldX = int(display_width/2)
        centerOfFieldY = int(display_height/2)

        numberOfNodes = N.amax(N.array(MESH_GRAPH).astype(int))
        for x in range(1, (numberOfNodes + 1)):
            retVal.append([x, \
            centerOfFieldX + ((display_height / 3) * N.sin((x - 2) * ((2 * N.pi) / numberOfNodes))), \
            centerOfFieldY - ((display_height / 3) * N.cos((x - 2) * ((2 * N.pi) / numberOfNodes)))])
    elif typeOfGraph == graphType.ALL_CONNECTED:
        centerOfFieldX = int(display_width/2)
        centerOfFieldY = int(display_height/2)

        numberOfNodes = N.amax(N.array(ALL_CONNECTED_GRAPH).astype(int))
        for x in range(1, (numberOfNodes + 1)):
            retVal.append([x, \
            centerOfFieldX + ((display_height / 3) * N.sin((x - 2) * ((2 * N.pi) / numberOfNodes))), \
            centerOfFieldY - ((display_height / 3) * N.cos((x - 2) * ((2 * N.pi) / numberOfNodes)))])
    elif typeOfGraph == graphType.TREE:
        buildTreeComputerLocations(retVal)
    elif typeOfGraph == graphType.LINE:
        numberOfNodes = N.amax(N.array(LINE_GRAPH).astype(int))
        for x in range(1, (numberOfNodes + 1)):
            yVal = None
            if x % 2 == 0:
                yVal = display_height/3
            else:
                yVal = 2*display_height/3
            retVal.append([x, x*display_width/numberOfNodes - 35, yVal])

    return retVal

class graphType(Enum):
    NONE          = 0
    RING          = 1
    STAR          = 2
    MESH          = 3
    ALL_CONNECTED = 4
    BUS           = 5
    HYBRID        = 6
    LINE          = 7
    TREE          = 8

class dataToDisplay:

    #this needs to be set to the type of graph (star, ring, etc)
    typeOfGraph = graphType.NONE
    

    #this list shall contain lists of tuples representing how the virus spreads.
    # 
    # Example:
    # [[(1,2), (1,3)]
    # [(1,4), (2,5), (2,6)]]
    #
    # in this example, during the first step of the simulation the virus spreads 
    # from node 1 to node 2, and node 1 to node 3. In the second step, it spreads 
    # from node 1 to node 4, and node 2 to nodes 5 and 6
    animationSteps = None
    def __init__(self):
        self.animationSteps = []

linesToDraw = []
defaultLines = []

def roundTuple(tuple):
    return (round(tuple[0]),round(tuple[1]))

def distanceBetweenTwoPoints(pointA, pointB):
    return ((pointB[0] - pointA[0])**2 + (pointB[1] - pointA[1])**2)**.5

def nodeToLocations(nodes, positionsInImage):
    retVal = []
    for node in nodes:
        x1 = positionsInImage[node[0]][1]
        y1 = positionsInImage[node[0]][2]
        x2 = positionsInImage[node[1]][1]
        y2 = positionsInImage[node[1]][2]
        retVal.append([(x1,y1),(x2,y2), 0])
    return retVal

def startAnimation(computerPositions, dataToDisplay):
    clock = pygame.time.Clock()
    done = False
    screen = None
    pygame.init()
    screen = pygame.display.set_mode((display_width,display_height))
    stepsDone = 0
    if len(dataToDisplay.animationSteps) == 0:
        return
    linesToDraw.append(nodeToLocations(dataToDisplay.animationSteps[0], computerPositions))

    while not done:
        hasCompletedALine = False
        iterationDone = False

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()

        if stepsDone == len(dataToDisplay.animationSteps):
                done = True
        elif len(linesToDraw[stepsDone]) == 0:
            stepsDone += 1
            print(dataToDisplay.animationSteps) 
            # if len(dataToDisplay.animationSteps) > stepsDone:
            linesToDraw.append(nodeToLocations(dataToDisplay.animationSteps[stepsDone], computerPositions))
            if hasCompletedALine:
                pygame.time.delay(3000)
            continue

        screen.fill((255,255,255))

        # draw the computer images at each node, and the faint gray lines
        if dataToDisplay.typeOfGraph == graphType.STAR:
            for x in range(1, computerPositions[:,0].size):
                numberPairs = [(computerPositions[1,1], computerPositions[1,2]), (computerPositions[x,1], computerPositions[x,2])]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)
        elif dataToDisplay.typeOfGraph == graphType.RING:
            numberPairs = [(computerPositions[-1,1], computerPositions[-1,2]), (computerPositions[1,1], computerPositions[1,2])]
            pygame.draw.lines(screen, (100,100,100), False, numberPairs,2)
            for x in range(2, computerPositions[:,0].size):
                numberPairs = [(computerPositions[x - 1,1], computerPositions[x - 1,2]), (computerPositions[x,1], computerPositions[x,2])]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)
        elif dataToDisplay.typeOfGraph == graphType.MESH:
            for edge in MESH_GRAPH:
                x1 = computerPositions[int(edge[0]),1]
                y1 = computerPositions[int(edge[0]),2]
                x2 = computerPositions[int(edge[1]),1]
                y2 = computerPositions[int(edge[1]),2]
                numberPairs = [(x1,y1),(x2,y2)]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)
        elif dataToDisplay.typeOfGraph == graphType.ALL_CONNECTED:
            for edge in ALL_CONNECTED_GRAPH:
                x1 = computerPositions[int(edge[0]),1]
                y1 = computerPositions[int(edge[0]),2]
                x2 = computerPositions[int(edge[1]),1]
                y2 = computerPositions[int(edge[1]),2]
                numberPairs = [(x1,y1),(x2,y2)]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)
        elif dataToDisplay.typeOfGraph == graphType.TREE:
            for edge in TREE_GRAPH:
                x1 = computerPositions[int(edge[0]),1]
                y1 = computerPositions[int(edge[0]),2]
                x2 = computerPositions[int(edge[1]),1]
                y2 = computerPositions[int(edge[1]),2]
                numberPairs = [(x1,y1),(x2,y2)]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)
        elif dataToDisplay.typeOfGraph == graphType.LINE:
            for edge in LINE_GRAPH:
                x1 = computerPositions[int(edge[0]),1]
                y1 = computerPositions[int(edge[0]),2]
                x2 = computerPositions[int(edge[1]),1]
                y2 = computerPositions[int(edge[1]),2]
                numberPairs = [(x1,y1),(x2,y2)]
                pygame.draw.lines(screen, (100,100,100), False, numberPairs, 2)

        for x in range(1, computerPositions[:,0].size):
            screen.blit(computerImage,  (computerPositions[x,1]-25, computerPositions[x,2]-25))


        #draw completed lines
        for x in range(stepsDone):
            for line in linesToDraw[x]:
                pygame.draw.lines(screen, (255,0,0), False, (line[0],line[1]),4)
        
        # draw in progress lines
        for line in linesToDraw[stepsDone]:
            totalDistance = distanceBetweenTwoPoints(line[0],line[1])
            x3 = line[0][0] + ((line[2]/totalDistance) * (line[1][0] - line[0][0]))
            y3 = line[0][1] + ((line[2]/totalDistance) * (line[1][1] - line[0][1]))
            toDraw = [line[0], (x3,y3)]
            pygame.draw.lines(screen, (255,0,0), False, toDraw, 4)

            if roundTuple(toDraw[1]) == roundTuple(line[1]):
                iterationDone = True
                hasCompletedALine = True
            else:
                line[2] += totalDistance/200
        
        pygame.display.update()

        if iterationDone == True:
            stepsDone += 1
            if stepsDone == len(dataToDisplay.animationSteps):
                done = True
            else:
                linesToDraw.append(nodeToLocations(dataToDisplay.animationSteps[stepsDone], computerPositions))
        clock.tick(60)

        

def display(data):
    computerLocations = N.array(getComputerLocationsOnDisplay(data.typeOfGraph))
    startAnimation(computerLocations, data)
    