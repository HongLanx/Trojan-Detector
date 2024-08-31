import subprocess
import json
import GoASTConverter


# 输入一个go文件，在其目录输出一个go自带ast库生成的ast文本文件
def get_go_ast(file_path):
    result = subprocess.run(['GolangTool/AstGenerator.exe', file_path], capture_output=True, text=True)


# 输入一个go文件，在其目录输出一个go自带ssa库生成的ssa中间代码
def get_go_ssa(file_path):
    result = subprocess.run(['GolangTool/SSAGenerator.exe', '-build=F', file_path], capture_output=True, text=True)


# 输入一个go文件，在其目录直接输出一个ast转换而来的JSON文件
def get_json_from_go_ast(file_path):
    get_go_ast(file_path)
    ast_path = ''.join(file_path.split('.')[:-1]) + ".ast"
    GoASTConverter.convert_ast_to_json(ast_path)


get_json_from_go_ast('test.go')
get_go_ssa('test.go')
