import subprocess
import json
import GoASTConverter

def get_go_ast(file_path):
    result = subprocess.run(['GolangTool/AstGenerator.exe', file_path], capture_output=True, text=True)


def get_go_ssa(file_path):
    result = subprocess.run(['GolangTool/SSAGenerator.exe', '-build=F',file_path], capture_output=True, text=True)

def get_json_from_go_ast(file_path):
    get_go_ast(file_path)
    ast_path=''.join(file_path.split('.')[:-1])+".ast"
    GoASTConverter.convert_ast_to_json(ast_path)

get_json_from_go_ast('test.go')
get_go_ssa('test.go')