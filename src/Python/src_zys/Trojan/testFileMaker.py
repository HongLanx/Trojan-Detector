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

maker = {0:fileMaker.star, 1:fileMaker.tree, 2:fileMaker.ring, 
            3:fileMaker.line , 4:fileMaker.fullConnected, 5:fileMaker.mesh }
shapes = {0:"star", 1:"tree", 2:"ring", 3:"line" , 4:"fullConnected", 5:"mesh" }
for shape in range(0,6):
    print("Entering", shapes[shape], "tests")
    for x in range (1,101,1):
        try:
            maker[shape](x)
            print("Test #", x,"passed") 
        except Exception as e:
            print("Error in test number",x, "for shape",shapes[shape])
            print(type(e))    # the exception instance
            print(e)          # __str__ allows args to be printed directly,
    print("")