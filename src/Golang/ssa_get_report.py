import json
import re

from src.Golang import ssa_analyzer
from src.Golang import ssa_patterns_fin


# 参数：提取后的项目信息（JSON格式），病毒木马模式类型
# 返回匹配得到的恶意评分与该模式的评分
# 初始恶意评分为0
# 第一次匹配要求完全匹配，若匹配成功则加上对应的分数，对于strings，多次匹配成功只记作匹配成功1次
# 由于JSON内的calls可能出现多次，对于calls的匹配，如果是第一次匹配，则总恶意评分加上对应的分数，后面每多匹配一次，在总恶意评分只加1
# 对于字符串，进行两轮匹配，分别是精确匹配和模糊匹配，模糊匹配的加分值比精确匹配低5分

def get_score_and_report(json_data, pattern, pattern_name=""):
    # 解析JSON数据
    project_info = json.loads(json_data)

    malicious_score = 0
    matched_calls = set()
    matched_strings = set()

    report = {
        "report_text": "",
        "severity": 0
    }

    report["report_text"] += f"{pattern_name}SSA中间代码模式匹配报告：\n\n"
    print("正在匹配函数调用...")

    # 匹配 Function Calls
    for call in project_info['calls']:
        if call in pattern['calls']:
            severity = pattern['calls'][call]
            if severity != 0:
                report["report_text"] += f"疑似{pattern_name}特征函数调用：{call}   危险度：{severity}\n"
            if call not in matched_calls:
                malicious_score += severity
            else:
                malicious_score += 1
            matched_calls.add(call)

    print("正在精确匹配字符串...")
    # 匹配 Strings
    for string in project_info['strings']:
        if string in pattern['strings']:
            if string not in matched_strings:
                severity = pattern['strings'][string]
                if severity!=0:
                    report["report_text"] += f"精确匹配：疑似{pattern_name}特征字符串：{string}    危险度：{severity}\n"
                malicious_score += severity
                matched_strings.add(string)

    print("正在模糊匹配字符串...")
    for found_string in project_info['strings']:
        # 检查每个模式是否在发现的字符串中
        for string, severity in pattern['strings'].items():
            # 使用正则表达式进行模糊匹配，例如匹配 '*ddos*' 等
            if re.search(r'.*{}.*'.format(re.escape(string)), found_string, re.IGNORECASE):
                # 确保每个模式只被计算一次
                if string not in matched_strings:
                    report[
                        "report_text"] += f"模糊匹配：疑似{pattern_name}特征字符串：{found_string}   危险度：{severity}\n"
                    # 如果匹配成功，并且原评分大于5，则加上原评分-5
                    if severity > 5:
                        malicious_score += (severity - 5)
                    matched_strings.add(string)
                    break  # 匹配到一个字符串后，不再尝试其他模式

    report["report_text"] += f"\n{pattern_name}SSA中间代码模式匹配结果：总危险度{malicious_score}\n"
    report["severity"] = malicious_score
    return report


# 输出最终报告
def output_ssa_matching_report(folder=None,is_html=False):
    analyse_project_info, analyse_project_folder = ssa_analyzer.project_to_ssa_json(folder,is_html)
    enc_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.encryption_patterns, "加密器")
    bot_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.botnet_patterns, "僵尸网络")
    phish_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.phishing_patterns, "钓鱼网络")
    obfuscate_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.obfuscation_patterns, "代码混淆")
    penetrate_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.penetration_patterns, "渗透测试")
    kernel_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.kernel_patterns, "内核攻击")
    bypass_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.Defense_Bypass_patterns, "防御绕过")
    ransom_report = get_score_and_report(analyse_project_info, ssa_patterns_fin.ransomware_patterns, "勒索软件")

    # 将所有报告放入一个列表
    reports = [
        enc_report, bot_report, phish_report, obfuscate_report,
        penetrate_report, kernel_report, bypass_report,
        ransom_report
    ]

    # 按severity从大到小排序
    reports.sort(key=lambda x: x['severity'], reverse=True)

    final_report = ""
    for report in reports:
        if report["severity"] != 0:
            final_report += report["report_text"] + "\n\n"
    report_path = analyse_project_folder + "/SSA中间代码模式匹配检测报告.txt"
    with open(report_path, "w", encoding='utf-8') as f:
        f.write(final_report)

    print(f"成功生成检测报告，位于{report_path}")
