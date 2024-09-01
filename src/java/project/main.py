import tkinter as tk
from tkinter import filedialog
import javalang
import json

def select_java_file():
    # 创建一个隐藏的主窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口

    # 打开文件选择对话框，让用户选择一个Java文件
    file_path = filedialog.askopenfilename(
        title="选择一个Java文件",
        filetypes=[("Java files", "*.java")]  # 只允许选择Java文件
    )
    return file_path

def read_java_file(file_path):
    # 读取Java源文件内容
    with open(file_path, 'r', encoding='utf-8') as file:
        java_code = file.read()
    return java_code

def parse_java_to_ast(java_code):
    # 使用javalang解析Java代码，生成AST树
    tree = javalang.parse.parse(java_code)
    return tree

def ast_to_dict(node):
    # 将AST节点转换为字典，便于转化为JSON
    if isinstance(node, javalang.ast.Node):
        node_dict = {
            "node_type": node.__class__.__name__,
            "attributes": {},
            "children": []
        }
        # 处理节点的属性
        for attr_name in node.attrs:
            attr_value = getattr(node, attr_name)
            if isinstance(attr_value, javalang.ast.Node):
                node_dict["attributes"][attr_name] = ast_to_dict(attr_value)
            elif isinstance(attr_value, list):
                node_dict["attributes"][attr_name] = [
                    ast_to_dict(item) if isinstance(item, javalang.ast.Node) else item
                    for item in attr_value
                ]
            elif isinstance(attr_value, set):
                node_dict["attributes"][attr_name] = list(attr_value)
            else:
                node_dict["attributes"][attr_name] = attr_value

        # 处理节点的子节点
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, javalang.ast.Node):
                        node_dict["children"].append(ast_to_dict(item))
            elif isinstance(child, javalang.ast.Node):
                node_dict["children"].append(ast_to_dict(child))

        return node_dict
    else:
        return str(node)  # 如果不是AST节点，直接返回其字符串表示

def convert_ast_to_json(ast_tree):
    # 将AST字典转换为JSON格式
    ast_dict = ast_to_dict(ast_tree)
    ast_json = json.dumps(ast_dict, indent=4, ensure_ascii=False)
    return ast_json

def save_json_to_file(json_data, output_file="ast_output.json"):
    # 将JSON数据保存到文件中
    with open(output_file, "w", encoding="utf-8") as json_file:
        json_file.write(json_data)

def main():
    file_path = select_java_file()
    if file_path:
        java_code = read_java_file(file_path)
        ast_tree = parse_java_to_ast(java_code)
        ast_json = convert_ast_to_json(ast_tree)
        save_json_to_file(ast_json)
        print("AST JSON has been saved to ast_output.json")
    else:
        print("未选择文件。")

if __name__ == "__main__":
    main()
