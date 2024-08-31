import subprocess
import json


def get_go_ast(file_path):
    result = subprocess.run(['GolangTool/AstGenerator.exe', file_path], capture_output=True, text=True)


def get_go_ssa(file_path):
    result = subprocess.run(['GolangTool/SSAGenerator.exe', '-build=F',file_path], capture_output=True, text=True)

get_go_ast('test.go')
get_go_ssa('test.go')