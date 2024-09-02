#!/usr/bin/env python3
"""
Cameron Padua
Group Project
fileMaker

This script will create different network shapes files. Currently it supports
star, mesh, fully connected, line, and tree. If you would like to create an 
individual file, you call the method responsible for creating it. By default, 
each method will create a network with 10 nodes that are bidirectional. If you
pass in an integer value to the method, you can vary the size of the number of
nodes. Additionally, you can call the main method to create every type of network
file. By default, they will all have 10 nodes, but if you pass a integer value,
you can vary the size.

Note: Code written for Python 3.6


Notes to Use:
    import fileMaker
    call individual methods
        Example
        fileMaker.star(n)


    IGNORE, ONLY USE IF YOU UN-COMMENT EVAL LINE AT THE BOTTOM
    if you are in a linux enviroment, make sure to chmod +x the file
    run the script by using ./fileMaker 'method()'
    for example ./fileMaker 'main(14)' or ./fileMaker 'star(14)'
    
    if you are using Windows, you will need to do something like (I think)
    pyhton fileMaker.py 'method(10)'
"""

import numpy as np
import random
import sys

def line(maxNode):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    #fileName = "line"+str(maxNode)+".txt"
    fileName = "line.txt"
    File = open(fileName,"w")
    
    for x in range(1,maxNode):
        writePairs(File, x, x+1)
    File.close()
    
    print("Line File made. File is named ", fileName)
    
def fullConnected(maxNode = 10):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    record = np.zeros((maxNode+1,maxNode+1),dtype=bool)
    #fileName = "fullyConnected"+str(maxNode)+".txt"
    fileName = "fullconnect.txt"
    File = open(fileName,"w")
    
    for x in range(1,maxNode):
    #create ring of values:
        writePairs(File, x, x+1)
        record[x, x+1] = True
        record[x+1, x] = True
        record[x, x] = True
    record[maxNode, maxNode] = True
    for y in range(1,maxNode+1):
        for x in range(1,maxNode+1):
            if(record[y, x] == False):
                writePairs(File, x, y)
                record[y, x] = True
                record[x, y] = True
                
    File.close()
    print("Fully connected File made. File is named ", fileName)
    
def mesh(maxNode = 10):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    record = np.zeros((maxNode+1,maxNode+1),dtype=bool)
    #fileName = "mesh"+str(maxNode)+".txt"
    fileName = "mesh.txt"
    File = open(fileName,"w")
    
    for x in range(1,maxNode):
    #remove self values from mix
        record[x, x] = True
    record[maxNode, maxNode] = True
    for y in range(1,maxNode+1):
        for x in range(1,maxNode+1):
            if random.random() > .8:
                if(record[y, x] == False):
                    writePairs(File, x, y)
                    record[y, x] = True
                    record[x, y] = True
                
    File.close()
    # print("Mesh File made. File is named ", fileName)
    
def ring(maxNode = 10):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    #fileName = "ring"+str(maxNode)+".txt"
    fileName = "ring.txt"
    File = open(fileName,"w")
    
    for x in range(1,maxNode):
        writePairs(File, x, x+1)
    writePairs(File, maxNode, 1)
    
    File.close()
    print("Ring File made. File is named ", fileName)
    
def star(maxNode = 10):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    #fileName = "star"+str(maxNode)+".txt"
    fileName = "star.txt"
    File = open(fileName,"w")
    
    for x in range(1,maxNode):
        writePairs(File, 1, x+1)
    File.close()
    
    print("Star File made. File is named ", fileName)
    
def tree(maxNode = 10):
    if(maxNode < 2):
        raise Exception('Cannot create shape with 1 node')
    #fileName = "tree"+str(maxNode)+".txt"
    fileName = "tree.txt"
    File = open(fileName,"w")

    currentNode = 1
    currentMaxNode = 2
    
    while(currentMaxNode <= maxNode):
        if currentNode*2 <= maxNode:
            writePairs(File, currentNode, currentMaxNode)
            currentMaxNode+=1
        if currentNode*2 +1 <= maxNode:
            writePairs(File, currentNode, currentMaxNode)
            currentMaxNode+=1
        currentNode+=1
    File.close()
    print("Tree File made. File is named ", fileName)

def writePairs(File, val1, val2):
    """
    Writes a pair of integers to a file.
    
    Input: File: a file object to write to. 
           val1: an integer to write to the file
           va12: an integer to write to the file
    Return: Nothing
    
    """         
    File.write(str(val1))
    File.write("\t")
    File.write(str(val2))
    File.write("\n")

def main(maxNumber = 10):
    line(maxNumber)
    ring(maxNumber)
    star(maxNumber)
    tree(maxNumber)
    fullConnected(maxNumber)
    mesh(maxNumber)

#eval(sys.argv[1])
