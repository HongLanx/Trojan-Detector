import os
import ast
import json
from custom_security_checks import run_plugin_str_checks  # 导入plugin_Str的检测功能


def read_python_file(file_path):
    # 读取Python源文件内容
    with open(file_path, 'r', encoding='utf-8') as file:
        python_code = file.read()
    return python_code


def parse_python_to_ast(python_code):
    # 使用ast解析Python代码，生成AST树
    tree = ast.parse(python_code)
    return tree


def ast_to_dict(node):
    # 将AST节点转换为字典，便于转化为JSON
    if isinstance(node, ast.AST):
        node_dict = {
            "node_type": node.__class__.__name__,
            "fields": {}
        }
        # 处理节点的字段
        for field_name, field_value in ast.iter_fields(node):
            if isinstance(field_value, ast.AST):
                node_dict["fields"][field_name] = ast_to_dict(field_value)
            elif isinstance(field_value, list):
                node_dict["fields"][field_name] = [
                    ast_to_dict(item) if isinstance(item, ast.AST) else item
                    for item in field_value
                ]
            else:
                node_dict["fields"][field_name] = field_value

        return node_dict
    else:
        return str(node)  # 如果不是AST节点，直接返回其字符串表示


def convert_ast_to_json(ast_tree):
    # 将AST字典转换为JSON格式
    ast_dict = ast_to_dict(ast_tree)
    ast_json = json.dumps(ast_dict, indent=4, ensure_ascii=False)
    return ast_json


def save_json_to_file(json_data, output_file):
    # 将JSON数据保存到文件中
    with open(output_file, "w", encoding="utf-8") as json_file:
        json_file.write(json_data)


def analyze_ast_node(node, report, parent=None):
    """
    递归遍历 AST 节点，并执行自定义操作。
    """
    if isinstance(node, ast.AST):
        node._PySec_parent = parent  # 为每个节点设置父节点属性
        issues = run_plugin_str_checks(node)
        report.extend(issues)

        # 递归处理子节点
        for child in ast.iter_child_nodes(node):
            analyze_ast_node(child, report, node)  # 传递当前节点作为子节点的父节点


def generate_report(report, output_file):
    """将检测结果保存为报告文件"""
    with open(output_file, "w", encoding="utf-8") as file:
        for issue in report:
            file.write(json.dumps(issue, indent=4) + "\n")


def process_directory(directory_path, output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)  # 创建输出目录

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                python_code = read_python_file(file_path)
                ast_tree = parse_python_to_ast(python_code)

                # 初始化检测报告
                report = []

                # 提取代码结构和模块依赖关系信息，并执行自定义操作
                analyze_ast_node(ast_tree, report)

                # 生成JSON文件
                ast_json = convert_ast_to_json(ast_tree)
                output_file_name = f"{os.path.splitext(file)[0]}.json"
                output_file_path = os.path.join(output_directory, output_file_name)
                save_json_to_file(ast_json, output_file_path)
                print(f"AST JSON for {file} has been saved to {output_file_path}")

                # 生成检测报告
                report_file_name = f"{os.path.splitext(file)[0]}_report.txt"
                report_file_path = os.path.join(output_directory, report_file_name)
                generate_report(report, report_file_path)
                print(f"Security report for {file} has been saved to {report_file_path}")


def main():
    directory_path = './directory_to_scan_test'
    output_directory = './output_json_files_test'
    process_directory(directory_path, output_directory)


if __name__ == "__main__":
    main()
