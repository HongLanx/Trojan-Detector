from enum import Enum
import numpy as N
import displayVirusSpread as disp


class State(Enum):
    """
        Description: state is an Enum type. none is for a non-node such as for the zeroth index/node
                     which is not used in the network. clean refers to a node that has not yet seen
                     any effect from a virus. All nodes at the initialization step are set to clean.
                     infected means a node is infected by a virus. susceptible means there is a higher
                     chance of getting infected by a virus but that has not happened yet. immune is when
                     a node has recovered from an infection and is now immune to all viruses.
     """
    none          = 0
    clean         = 1
    infected      = 2
    susceptible    = 3
    immune        = 4

class GraphType(Enum):
    """
        Description: graphType is an Enum type. NONE is for a node that does not represent the network.
                     For example zeroth node and/or index is not considered a node in the network. All
                     other network types are given numbers from 1 to 8 that represents a particular type
                     of network.
     """
    NONE          = 0
    RING          = 1
    STAR          = 2
    MESH          = 3
    ALL_CONNECTED = 4
    BUS           = 5
    HYBRID        = 6
    LINE          = 7
    TREE          = 8

class Node:
    """
        Description: Node class represents a computer in the network. nodeID is used to identify
                     the node, adjacentNodes is a list that stores a nodes directly connected neighbors.
                     susceptibility var tells us if a node becomes susceptible to getting infectede
                     from a virus.
    """
    nodeID = -1
    adjacentNodes = None
    susceptibility = None
    status = None
    def __init__(self, nodeNum, nodeStrengthRange):
        self.nodeID = nodeNum
        self.susceptibility = N.random.uniform(nodeStrengthRange[0], nodeStrengthRange[1])
        self.adjacentNodes = []
        self.status = State.clean


class Network:
    """
        Description: Network class holds all nodes in the network. nodes is a dictionary
                     which stores a Node object for each corresponding node number. infectedList
                     is a list, the index of which represents that particular node and the value
                     it holds (defined enums per the state class) tells us the current status
                     of the node corresponding to that index. networkType holds a value that
                     represents the type of network that is being created.
                     createnetwork() method takes as input a string filename and passed it onto
                     drawGraphFromFile() class which returns a list of pairs of numbers. Each pair
                     of numbers represents a connection between those two nodes. The function uses each
                     pair to construct a Node object and a dictionary item and insert them into the
                     corresponding data structure.
    """
    nodes = None
    infectedList = None
    networkType = GraphType.NONE

    def __init__(self, type):
        self.nodes = {}
        self.networkType = type
        self.infectedList = [State.none]

    def createnetwork(self, filename, nodeStrengthRange = (0, 1)):
        """
            Description: creates a network from a list of pair of numbers. For each pair in the
                         list returned by drawGraphFromFile, if the 1st number in the pair is not already in
                         nodes dictionary, a new Node is created for that number and the adjacentNodes
                         list in the Node objects gets appended the second number in the pair as a neighbor.
                         The infected list also gets appended a state.clean value to mark that a node
                         with initial status is added. Later, the index will represent the node corresponding
                         to that number. If the there's already a node for that 1st number, only the
                         adjacentNodes list will get updated. Same steps will be followed for the second
                         number in the pair.
            Pre-Condition: filename as a string
            Post-Condition: nodes contains the node numbers as keys and Nodes as values, infectedList
                            contains a list of state.none values from index 1 to the highest index read
                            from the file. Index 0 will not be used since it is not in the network.
        """
        graphArray = disp.drawGraphFromFile(filename)
        for pair in graphArray:
            lhs = int(pair[0])
            rhs = int(pair[1])
            if lhs not in self.nodes:
                self.infectedList.append(State.clean)
                self.nodes[lhs] = Node(lhs, nodeStrengthRange)
                self.nodes[lhs].adjacentNodes.append(rhs)
            else:
                self.nodes[lhs].adjacentNodes.append(rhs)
            if rhs not in self.nodes:
                self.infectedList.append(State.clean)
                self.nodes[rhs] = Node(rhs, nodeStrengthRange)
                self.nodes[rhs].adjacentNodes.append(lhs)
            else:
                self.nodes[rhs].adjacentNodes.append(lhs)
            
