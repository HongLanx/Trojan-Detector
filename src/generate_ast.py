import javalang
import json
import sys

def generate_ast(java_file_path, output_json_path):
    with open(java_file_path, 'r') as file:
        source_code = file.read()

    # 解析Java源代码
    tree = javalang.parse.parse(source_code)

    # 将AST转换为JSON
    ast_json = to_json(tree)

    # 将JSON写入文件
    with open(output_json_path, 'w') as json_file:
        json.dump(ast_json, json_file, indent=4)

    print(f"AST JSON has been written to {output_json_path}")

def to_json(tree):
    # Convert the javalang AST to a JSON-serializable dictionary
    def node_to_dict(node):
        if isinstance(node, javalang.tree.Node):
            node_dict = node.__dict__
            for key, value in node_dict.items():
                if isinstance(value, list):
                    node_dict[key] = [node_to_dict(v) for v in value if isinstance(v, javalang.tree.Node)]
                elif isinstance(value, javalang.tree.Node):
                    node_dict[key] = node_to_dict(value)
            return node_dict
        return str(node)

    return node_to_dict(tree)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python generate_ast.py <source_file> <output_file>")
    else:
        generate_ast(sys.argv[1], sys.argv[2])
