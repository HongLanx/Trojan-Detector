import json
import sys

def analyze_ast(json_file_path):
    with open(json_file_path, 'r') as json_file:
        ast_json = json.load(json_file)

    # 打印AST结构
    print("Java AST Structure:")
    print_ast(ast_json, 0)

def print_ast(node, indent):
    indent_string = ' ' * indent
    if isinstance(node, dict):
        for key, value in node.items():
            print(f"{indent_string}{key}:")
            print_ast(value, indent + 2)
    elif isinstance(node, list):
        for item in node:
            print_ast(item, indent)
    else:
        print(f"{indent_string}{node}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python analyze_ast.py <json_file>")
    else:
        analyze_ast(sys.argv[1])
