import os
import json

def load_json_file(file_path):
    # 读取并解析JSON文件
    with open(file_path, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return data

def check_malicious_patterns(ast_dict):
    # 定义要检测的恶意模式
    suspicious_patterns = {
        "exec_call": "exec",
        "eval_call": "eval",
        "suspicious_imports": ["os", "subprocess"]
    }

    def check_node(node):
        # 检查当前节点是否包含恶意模式
        if isinstance(node, dict):
            node_type = node.get("node_type")
            fields = node.get("fields", {})

            # 检查函数调用是否是exec或eval
            if node_type == "Call":
                func_name = fields.get("func", {}).get("id")
                if func_name in suspicious_patterns.values():
                    print(f"Suspicious call to {func_name} found.")

            # 检查导入模块
            if node_type == "Import":
                for alias in fields.get("names", []):
                    module_name = alias.get("name")
                    if module_name in suspicious_patterns["suspicious_imports"]:
                        print(f"Suspicious import of {module_name} found.")

            # 递归检查子节点
            for key, value in fields.items():
                if isinstance(value, dict):
                    check_node(value)
                elif isinstance(value, list):
                    for item in value:
                        check_node(item)

    check_node(ast_dict)

def process_json_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                print(f"\nProcessing {file_path}...")
                ast_dict = load_json_file(file_path)
                check_malicious_patterns(ast_dict)

def main():
    json_directory = './output_json_files'  # 读取之前保存的json文件的目录
    process_json_directory(json_directory)

if __name__ == "__main__":
    main()
