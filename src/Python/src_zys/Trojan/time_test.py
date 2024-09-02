import simulateVirusSpread as sim
import displayVirusSpread as disp
import viruses
import Network as n
import fileMaker as fm
import numpy as N
import matplotlib.pyplot as plt



#pick the type of malware you want to simulate:

#virus = viruses.SuperVirus()
#virus = viruses.LogicBomb()
#virus = viruses.Trojan()
virus = viruses.Worm()

# list that holds count of animation steps.
time_taken = []

size_of_network = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

"""
    simulate all type of networks:
    for each loop, the size of networks increase by 10

    Output:
            2-D array, where rows represent the simulation steps took until
            malware finish propagating, columns represent the the type of 
            network in order of line, ring, star, tree, full connected, and mesh.

"""
for i in range(len(size_of_network)):
    # this will create the text input file that holds data for creating diffrent
    # size of newtworks
    fm.main(size_of_network[i])

    # Creates all type of networks
    line_Network = n.Network(disp.graphType.LINE)
    line_Network.createnetwork("line.txt")
    ring_Network = n.Network(disp.graphType.RING)
    ring_Network.createnetwork("ring.txt")
    star_Network = n.Network(disp.graphType.STAR)
    star_Network.createnetwork("star.txt")
    tree_Network = n.Network(disp.graphType.TREE)
    tree_Network.createnetwork("tree.txt")
    all_connected_Network = n.Network(disp.graphType.ALL_CONNECTED)
    all_connected_Network.createnetwork("fullconnect.txt")
    mesh_Network = n.Network(disp.graphType.MESH)
    mesh_Network.createnetwork("mesh.txt")


    # simulating propagation for each type of network for once. 
    time_turns1,infectionRates, percent_infected = sim.runOnce(line_Network, 1, virus, False)
    time_turns2,infectionRates, percent_infected = sim.runOnce(ring_Network, 1, virus, False)
    time_turns3,infectionRates, percent_infected = sim.runOnce(star_Network, 1, virus, False)
    time_turns4,infectionRates, percent_infected = sim.runOnce(tree_Network, 1, virus, False)
    time_turns5,infectionRates, percent_infected = sim.runOnce(all_connected_Network, 1, virus, False)
    time_turns6,infectionRates, percent_infected = sim.runOnce(mesh_Network, 1, virus, False)

    time_taken.append(time_turns1)
    time_taken.append(time_turns2)
    time_taken.append(time_turns3)
    time_taken.append(time_turns4)
    time_taken.append(time_turns5)
    time_taken.append(time_turns6)

# reshape so that it has 2d array of
# rows = size of network
# columns = shape of network

time_taken = N.reshape(time_taken, [10, 6])

# output that shows the steps malware took to propagate until the point it has to stop.
print(time_taken)

# network data depending on the size of network 10 - 100 for each shape of network
line_data = N.array(time_taken[:, 0])
ring_data = N.array(time_taken[:, 1])
star_data = N.array(time_taken[:, 2])
tree_data = N.array(time_taken[:, 3])
fullconnect_data = N.array(time_taken[:, 4])
mesh_data = N.array(time_taken[:, 5])


# drawing graph to compare the time malware took to finish propagating.
fig = plt.figure()
plt.plot(size_of_network, line_data)
plt.plot(size_of_network, ring_data)
plt.plot(size_of_network, star_data)
plt.plot(size_of_network, tree_data)
plt.plot(size_of_network, fullconnect_data)
plt.plot(size_of_network, mesh_data)
plt.xlabel("Size of Network")
plt.ylabel("time")
plt.legend(['line', 'ring', 'star', 'tree', 'full_connect' , 'mesh'] , loc='upper left')
plt.title("Worm Infection")
plt.show()

