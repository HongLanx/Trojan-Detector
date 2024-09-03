import ast
import json

# 定义可疑特征库
suspicious_imports = {"os", "sys", "subprocess", "socket", "requests", "threading", "base64", "logging", "cryptography", "pynput"}
suspicious_functions = {"dump_data", "download_malicious_code", "decode_hostname", "decode_port", "write_to_file", 
                        "encrypt_file", "decrypt_file", "handle_client", "receive_commands", "infect_files", "on_press", "replicate"}
suspicious_function_calls = {"os.system", "subprocess.Popen", "socket.socket", "socket.connect", "socket.recv", 
                             "socket.bind", "socket.listen", "socket.accept", "requests.get", "base64.b64decode", 
                             "open", "write", "remove", "Fernet.encrypt", "Fernet.decrypt", "pynput.keyboard.Listener"}

# 自定义AST解析器，将AST树转换为JSON格式
class ASTtoJSON(ast.NodeVisitor):
    def __init__(self):
        self.tree = []

    def generic_visit(self, node):
        node_type = type(node).__name__
        node_dict = {'node_type': node_type}

        for key, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                node_dict[key] = self.generic_visit(value)
            elif isinstance(value, list):
                node_dict[key] = [self.generic_visit(v) if isinstance(v, ast.AST) else v for v in value]
            else:
                node_dict[key] = value

        self.tree.append(node_dict)
        return node_dict

    def get_json(self):
        return json.dumps(self.tree, indent=4)

# 解析代码并生成AST树
def parse_code_to_ast_json(code):
    tree = ast.parse(code)
    json_visitor = ASTtoJSON()
    json_visitor.visit(tree)
    return json_visitor.get_json()

# 模式匹配函数
def match_pattern(ast_json, pattern):
    matched_nodes = []
    for node in ast_json:
        if all(item in node.items() for item in pattern.items()):
            matched_nodes.append(node)
    return matched_nodes

# 构建模式列表
patterns = []

# 可疑导入模式
for name in suspicious_imports:
    patterns.append({"node_type": "Import", "names": [{"name": name}]})

# 可疑函数定义模式
for name in suspicious_functions:
    patterns.append({"node_type": "FunctionDef", "name": name})

# 可疑函数调用模式
for name in suspicious_function_calls:
    patterns.append({"node_type": "Call", "func": {"id": name}})

# 读取并解析文件，并进行模式匹配
def analyze_file_with_patterns(file_path, patterns):
    with open(file_path, 'r', encoding='utf-8') as file:
        code_content = file.read()

    ast_json_str = parse_code_to_ast_json(code_content)
    ast_json = json.loads(ast_json_str)
    matches = []

    for pattern in patterns:
        matches.extend(match_pattern(ast_json, pattern))

    return matches

# 主程序
if __name__ == "__main__":
    file_paths = [
        '/mnt/data/adware.py',
        '/mnt/data/Dropper.py',
        '/mnt/data/infector.py',
        '/mnt/data/keylogger.py',
        '/mnt/data/ransomware.py',
        '/mnt/data/server.py',
        '/mnt/data/trojan.py',
        '/mnt/data/worm.py'
    ]

    for file_path in file_paths:
        matches = analyze_file_with_patterns(file_path, patterns)
        print(f"Matches in {file_path}:")
        print(json.dumps(matches, indent=4))



# 每个文件会输出所有与可疑特征匹配的AST节点。如果在某个文件中发现了匹配项，则会输出该匹配项的详细信息。这些信息可以帮助你识别和分析代码中的潜在恶意行为。
# 通过运行这个代码，你可以检测并分析文件中的潜在恶意代码特征，输出与这些特征匹配的AST节点信息。