import ast
import pickle
import os

def print_ast(node, indent=""):
    """递归打印 AST 树的结构"""
    if isinstance(node, ast.AST):
        print(indent + node.__class__.__name__)
        indent += "    "
        for field in node._fields:
            value = getattr(node, field, None)
            if isinstance(value, list):
                for item in value:
                    print(f"{indent}{field}:")
                    print_ast(item, indent + "    ")
            else:
                print(f"{indent}{field}:")
                print_ast(value, indent + "    ")
    else:
        print(indent + str(node))

def generate_and_store_ast(file_path):
    with open(file_path, 'r') as file:
        code = file.read()

    # 生成 AST 树
    tree = ast.parse(code)

    # 打印 AST 树的结构
    print(f"AST structure for {file_path}:")
    print_ast(tree)

    # 将 AST 树保存到文件
    ast_tree_file = f'{file_path}.ast'
    with open(ast_tree_file, 'wb') as ast_file:
        pickle.dump(tree, ast_file)

    print(f"AST tree saved to {ast_tree_file}")
    return ast_tree_file

def process_directory(directory_path):
    ast_files = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                print(f"\nProcessing {file_path}...")
                ast_file = generate_and_store_ast(file_path)
                ast_files.append(ast_file)
    return ast_files
