import json
import re
import os


def process_ast_text(input_text):
    # 使用正则表达式去除每行开头的数字、点和多余的空格
    cleaned_lines = []
    for line in input_text:
        # 从每行的起始位置去除数字和点，再去除随后的空格
        cleaned_line = re.sub(r'^\s*\d+\s*\.*\s*', '', line)
        # 进一步去除中间剩余的点及其前后的空格
        cleaned_line = re.sub(r'^(\.  )+(?=\S)', '', cleaned_line, flags=re.MULTILINE)
        cleaned_lines.append(cleaned_line)

    # 将清理后的文本重新拼接为字符串
    result_text = ''.join(cleaned_lines)
    return result_text


def parse_to_json(lines):
    stack = [{}]
    current_obj = stack[0]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 检测行缩进以确定层级
        depth = len(stack) - 1
        if line.endswith('{'):
            # 新对象的开始
            key = line.split(' ')[0]
            new_obj = {}
            if key.endswith('[]'):
                if key[:-2] not in stack[-1]:
                    stack[-1][key[:-2]] = []
                stack[-1][key[:-2]].append(new_obj)
            else:
                stack[-1][key] = new_obj
            stack.append(new_obj)
        elif line == '}':
            # 对象结束
            stack.pop()
        else:
            # 处理键值对
            if ': ' in line:
                key, value = line.split(': ', 1)
                value = value.replace('"', '')  # 移除字符串的引号
                stack[-1][key] = value

    return stack[0]


def convert_ast_to_json(file_path):
    file_path_base = ''.join(file_path.split('.')[:-1])
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.readlines()

    # 处理文本
    processed_text = process_ast_text(content)
    lines = processed_text.split('\n')

    ast_dict = parse_to_json(lines)

    # 将解析结果写入JSON文件
    json_output_path = f'{file_path_base}.json'
    with open(json_output_path, 'w',encoding='utf-8') as f:
        json.dump(ast_dict, f, indent=4, ensure_ascii=False)


# 测试用例
convert_ast_to_json('test.ast')
