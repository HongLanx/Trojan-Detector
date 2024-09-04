import json
import re
import ssa_info
import os
from collections import Counter
import ssa_getter
import tkinter as tk
from tkinter import filedialog


def process_ssa_code_from_file(file_path):
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8') as file:
        ssa_code = file.read()

    # 将 SSA 代码按行分割
    lines = ssa_code.strip().splitlines()

    # 初始化结果数组
    functions = []

    # 初始化当前处理的函数和代码块
    current_function = None
    current_block = None

    for line in lines:
        # 匹配函数定义行
        if line.startswith("func "):
            # 如果当前有正在处理的函数，先将其加入函数数组中
            if current_function is not None:
                functions.append(current_function)

            # 初始化新的函数对象
            current_function = {
                "name": line.strip(),  # 保留函数定义行作为函数名
                "blocks": []  # 初始化代码块数组
            }
            current_block = None

        # 检查代码块的开始
        elif re.match(r'\d+:', line):
            # 如果当前有正在处理的代码块，先将其加入代码块数组中
            if current_block is not None:
                current_function["blocks"].append(current_block)

            # 初始化新的代码块
            current_block = ""

        elif current_block is not None and line.strip():
            # 处理代码块中的行，提取直到遇到连续两个及以上空格为止的字符串
            # 并且只保留包含等号的行
            # if '=' in line:  # 如果要保留ifelse等选择语句，删除该条件即可
            trimmed_line = re.split(r'\s{2,}', line.strip())[0]
            # 将处理后的结果加入当前代码块，并添加换行符
            current_block += trimmed_line + "\n"

    # 最后一个代码块需要手动添加到当前函数中
    if current_block is not None:
        current_function["blocks"].append(current_block)

    # 最后一个函数需要手动添加到函数数组中
    if current_function is not None:
        functions.append(current_function)

    return functions


def process_folder(folder_path):
    SSA_path = folder_path + "/SSAFiles"
    project_info = {
        "calls": [],
        "strings": []
    }
    files = os.listdir(SSA_path)
    # 遍历文件夹中所有文件
    for file in files:
        if file.endswith('.ssa'):
            print(f"正在处理文件{SSA_path}/{file}")
            file_path = os.path.join(SSA_path, file)
            result = process_ssa_code_from_file(file_path)

            file_info = {
                "calls": [],
                "strings": []
            }
            for func in result:
                for block in func["blocks"]:
                    info = ssa_info.parse_code(block)
                    file_info["calls"].extend(info["calls"])
                    file_info["strings"].extend(info["strings"])

            project_info["calls"].extend(file_info["calls"])
            project_info["strings"].extend(file_info["strings"])

    return project_info


def summarize_info(project_info):
    # 使用Counter来统计calls和strings中每个元素的出现次数
    calls_count = Counter(project_info['calls'])
    strings_count = Counter(project_info['strings'])

    # 格式化输出，按照您给出的示例结构
    summarized_info = {
        "calls": dict(calls_count),  # 转换Counter对象为字典
        "strings": dict(strings_count)
    }
    return summarized_info


# 示例用法：传入文件夹路径，在文件夹下生成SSA关键信息的JSON文件
def generate_json(folder_path):
    project_info = summarize_info(process_folder(folder_path))
    result_file_path = os.path.join(folder_path, "SSAResult.json")

    with open(result_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(project_info, json_file, indent=4)
    return json.dumps(project_info, indent=4)


# 参数为：文件夹（也可以不输入参数，会跳出窗口让你选择文件夹），将文件夹内的所有go文件转换为SSA，再解析提取关键信息得到json_data
def project_to_ssa_json(folder_selected=None):
    json_data = None
    if not folder_selected:
        root = tk.Tk()
        root.withdraw()  # Hide the main tkinter window
        folder_selected = r'' + filedialog.askdirectory()
    if folder_selected:
        # 如果已经生成了SSA解析结果，直接返回结果即可
        if os.path.exists(os.path.join(folder_selected, "SSAResult.json")):
            return generate_json(folder_selected), folder_selected
        ssa_getter.get_ssa_from_folder(folder_selected)
        json_data = generate_json(folder_selected)
        print(f"已处理完项目: {folder_selected}")
    else:
        print("未选择文件夹")
    return json_data, folder_selected


# # 对单个文件进行处理示例
# file_info = {
#     "calls": [],
#     "strings": []
# }
# result = process_ssa_code_from_file("test.ssa")
#
# # 打印结果
# for func in result:
#     # print("Function:", func["name"])
#     for i in range(len(func["blocks"])):
#         block = func["blocks"][i]
#         info = ssa_info.parse_code(block)
#         print(f"block {i}:")
#         print("Function Calls:", info["calls"])
#         print("Strings:", info["strings"])
#         file_info["calls"].extend(info["calls"])
#         file_info["strings"].extend(info["strings"])
# # print(file_info["calls"])
# # print(file_info["strings"])
# print(json.dumps(file_info, indent=4))

# generate_json('try')
