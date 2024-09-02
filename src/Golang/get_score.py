import json
import re
# 参数：提取后的项目信息（JSON格式），病毒木马模式类型
# 返回匹配得到的恶意评分
# 初始恶意评分为0
# 第一次匹配要求完全匹配，若匹配成功则加上对应的分数，对于Imports和string，多次匹配成功只记作匹配成功1次
# 由于JSON内的calls可能出现多次，对于calls和FunctionCalls的匹配，如果是第一次匹配，则总恶意评分加上对应的分数，后面每多匹配一次，在总恶意评分只加1
# 对于字符串，进行两轮匹配，分别是精确匹配和模糊匹配，模糊匹配的加分值比精确匹配低5分

def get_score_from_info(json_data, pattern):
    # 解析JSON数据
    project_info = json.loads(json_data)

    malicious_score = 0
    matched_imports = set()
    matched_calls = set()
    matched_strings = set()

    print("正在匹配Imports...")
    # 匹配 Imports
    for imp in project_info['imports']:
        if imp in pattern['Imports']:
            if imp not in matched_imports:
                print(f"发现疑似僵尸网络特征Import：{imp}")
                malicious_score += pattern['Imports'][imp]
                matched_imports.add(imp)

    print("正在匹配函数调用...")
    # 匹配 Function Calls
    for call in project_info['calls']:
        func_name = call['function']
        if func_name in pattern['FunctionCalls']:
            print(f"发现疑似僵尸网络特征函数调用：{func_name} 于 {call['location']}")
            if func_name not in matched_calls:
                malicious_score += pattern['FunctionCalls'][func_name]
            else:
                malicious_score += 1
            matched_calls.add(func_name)

    print("正在精确匹配字符串...")
    # 匹配 Strings
    for string in project_info['string']:
        if string in pattern['Strings']:
            if string not in matched_strings:
                print(f"精确匹配：发现疑似僵尸网络特征字符串：{string}")
                malicious_score += pattern['Strings'][string]
                matched_strings.add(string)

    print("正在模糊匹配字符串...")
    for found_string in project_info['string']:
        # 检查每个模式是否在发现的字符串中
        for string, score in pattern['Strings'].items():
            # 使用正则表达式进行模糊匹配，例如匹配 '*ddos*' 等
            if re.search(r'.*{}.*'.format(re.escape(string)), found_string, re.IGNORECASE):
                # 确保每个模式只被计算一次
                if string not in matched_strings:
                    print(f"模糊匹配：发现疑似僵尸网络特征字符串：{found_string}")
                    # 如果匹配成功，并且原评分大于5，则加上原评分-5
                    if score > 5:
                        malicious_score += (score - 5)
                    matched_strings.add(string)
                    break  # 匹配到一个字符串后，不再尝试其他模式

    return malicious_score
