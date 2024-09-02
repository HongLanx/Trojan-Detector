import displayVirusSpread as disp

displayData = disp.dataToDisplay()
# displayData.animationSteps.append([(1,2),(1,4)])
# displayData.animationSteps.append([(1,3),(1,5),(1,6)])
# displayData.animationSteps.append([(1,7),(1,8)])
# displayData.typeOfGraph = disp.graphType.STAR

# displayData.animationSteps.append([(1,2), (1,8)])
# displayData.animationSteps.append([(2,3), (8,7)])
# displayData.typeOfGraph = disp.graphType.RING

# displayData.animationSteps.append([(1,2), (1,8), (1,3)])
# displayData.animationSteps.append([(3,4), (3,5)])
# displayData.typeOfGraph = disp.graphType.MESH

# displayData.animationSteps.append([(1,2), (1,8), (1,3)])
# displayData.animationSteps.append([(3,4), (3,5)])
# displayData.typeOfGraph = disp.graphType.ALL_CONNECTED

# displayData.animationSteps.append([(1,2),(1,3)])
# displayData.animationSteps.append([(2,4),(2,5),(3,6),(3,7)])
# displayData.animationSteps.append([(4,8)])
# displayData.typeOfGraph = disp.graphType.TREE

displayData.animationSteps.append([(1,2)])
displayData.animationSteps.append([(2,3)])
displayData.animationSteps.append([(3,4)])
displayData.animationSteps.append([(4,5)])
displayData.animationSteps.append([(5,6)])
displayData.animationSteps.append([(6,7)])
displayData.animationSteps.append([(7,8)])
displayData.typeOfGraph = disp.graphType.LINE

disp.display(displayData)