"""
此脚本使用已训练的机器学习模型（随机森林分类器）来预测并报告SSA（Static Single Assignment）代码中潜在的恶意行为。主要功能如下：
1. 加载由SSA代码生成的项目信息，并将其转换为机器学习模型可以理解的格式。
2. 使用多个预训练的机器学习模型，每个模型对应一种特定的恶意行为模式（如加密器、僵尸网络、钓鱼网络等）。
3. 对每个项目信息进行预测，判断其是否符合已知的恶意模式。
4. 根据模型的预测概率，输出详细的匹配报告，包括预测结果和概率。
5. 将所有检测报告按照预测概率从高到低排序，并格式化输出到一个文本文件中。
"""

import json

from src.Golang import ssa_analyzer
from src.Golang import ssa_patterns_fin
from src.Golang.machine_learning import predict_with_model


def output_machine_learning_matching_report(folder=None,is_html=False):
    analyse_project_info, analyse_project_folder = ssa_analyzer.project_to_ssa_json(folder,is_html)
    analyse_project_info = json.loads(analyse_project_info)
    enc_report = predict_with_model("src/Golang/model/encryption_model.pkl", analyse_project_info,
                                    ssa_patterns_fin.encryption_patterns)
    bot_report = predict_with_model("src/Golang/model/botnet_model.pkl", analyse_project_info, ssa_patterns_fin.botnet_patterns)
    phish_report = predict_with_model("src/Golang/model/phishing_model.pkl", analyse_project_info,
                                      ssa_patterns_fin.phishing_patterns)
    obfuscate_report = predict_with_model("src/Golang/model/obfuscation_model.pkl", analyse_project_info,
                                          ssa_patterns_fin.obfuscation_patterns)
    penetrate_report = predict_with_model("src/Golang/model/penetration_model.pkl", analyse_project_info,
                                          ssa_patterns_fin.penetration_patterns)
    kernel_report = predict_with_model("src/Golang/model/kernel_model.pkl", analyse_project_info, ssa_patterns_fin.kernel_patterns)
    bypass_report = predict_with_model("src/Golang/model/bypass_model.pkl", analyse_project_info,
                                       ssa_patterns_fin.Defense_Bypass_patterns)
    ransom_report = predict_with_model("src/Golang/model/ransome_model.pkl", analyse_project_info,
                                       ssa_patterns_fin.ransomware_patterns)

    # 将所有报告放入一个列表
    reports = [
        enc_report, bot_report, phish_report, obfuscate_report,
        penetrate_report, kernel_report, bypass_report,
        ransom_report
    ]

    # 按severity从大到小排序
    reports.sort(key=lambda x: x['probability'], reverse=True)

    final_report = ""
    for report in reports:
        if report:
            if report == enc_report:
                final_report += "加密器特征-机器学习模型检测报告：\n"
            if report == bot_report:
                final_report += "僵尸网络特征-机器学习模型检测报告：\n"
            if report == phish_report:
                final_report += "钓鱼网络特征-机器学习模型检测报告：\n"
            if report == obfuscate_report:
                final_report += "代码混淆特征-机器学习模型检测报告：\n"
            if report == penetrate_report:
                final_report += "渗透测试特征-机器学习模型检测报告：\n"
            if report == kernel_report:
                final_report += "内核攻击特征-机器学习模型检测报告：\n"
            if report == bypass_report:
                final_report += "防御绕过特征-机器学习模型检测报告：\n"
            if report == ransom_report:
                final_report += "勒索软件特征-机器学习模型检测报告：\n"
            final_report += report["report_probability"] + "\n"

            # 样本特征重要性报告，可选
            # final_report += report["report_importance"] + "\n"

    report_path = analyse_project_folder + "/代码特征向量化-随机森林模型检测报告.txt"

    with open(report_path, "w", encoding='utf-8') as f:
        f.write(final_report)

    print(f"成功生成检测报告，位于{report_path}")
