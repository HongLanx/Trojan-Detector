import Network as n
import displayVirusSpread as disp
import numpy as N



def nowhereToGo(network):
  count = 1
  for node in network.infectedList[1:]:
    if node == n.State.infected:
      for neighbor in network.nodes[count].adjacentNodes:
        if network.infectedList[neighbor] != n.State.infected and network.infectedList[neighbor] != n.State.immune:  
          return False
    count += 1
  return True

def runOnce(network, startingPoint, virus, displayAnimation = True):
    network.infectedList[startingPoint] = n.State.infected
    simulationNotOver = True
    
    displayData = disp.dataToDisplay()
    displayData.typeOfGraph = network.networkType
    
    #analysis variables
    count = 0
    infectedCount = 0
    rate = 0
    infectionRates = []
    
    percent_infected = []
    percent_infected.append(percentage(network))
    
    while simulationNotOver == True:
      count+=1
      hasNewAnimationInfo = False
      currentTurnMoves = []
      # currentNodeID = 1
      for x in range(1, len(network.infectedList)):
        if network.infectedList[x] == n.State.infected:
          for neighbor in network.nodes[x].adjacentNodes:
            if network.infectedList[neighbor] != n.State.infected:  
              if virus.infectOrNot(network, neighbor, x):
                currentTurnMoves.append((x, neighbor))
                hasNewAnimationInfo = True
      rate, infectedCount = checkRate(network, infectedCount)
      infectionRates.append(rate)
      percent_infected.append(percentage(network))
      for move in currentTurnMoves:
        network.infectedList[move[1]] = n.State.infected
      if hasNewAnimationInfo:
        displayData.animationSteps.append(currentTurnMoves)
      
      if nowhereToGo(network):
        simulationNotOver = False  
        if displayAnimation:
          disp.display(displayData)
    return count,infectionRates, percent_infected

def checkRate(network, lastInfectedCount):
    infected_nodes_count = network.infectedList.count(n.State.infected)
    if(infected_nodes_count > lastInfectedCount):
        return infected_nodes_count - lastInfectedCount, infected_nodes_count
    else:
        return 0, lastInfectedCount    
        
def percentage(network):
    newList = N.array(network.infectedList)
    infected_nodes = N.where(newList == n.State.infected)
    return 100.0 * len(infected_nodes) / len(network.nodes)

