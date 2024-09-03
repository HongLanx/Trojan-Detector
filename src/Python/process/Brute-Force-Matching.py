import re

# 定义正则表达式模式
string_patterns = {
    r'User-Agent': 6,  # 可能用于伪装成合法用户或爬虫
    r'Weeman': 8,  # 钓鱼工具的名称，可能在恶意代码中出现
    r'action_url': 7,  # 可能是钓鱼表单的提交目标
    r'Please install beautifulsoup 4': 7,  # 工具依赖的提示信息
    r'clone\(\)': 8,  # 可能用于克隆合法网站以进行钓鱼
    r'history\.log': 7,  # 日志文件，可能用于记录钓鱼数据
    r'root@phishmailer:~': 8,  # 钓鱼工具的提示符，可能用于引导用户进行恶意操作
    r'Your Templates Will Be Saved Here': 7,  # 钓鱼模板保存路径的提示
    r'Phish': 9,  # 明示钓鱼意图的字符串
    r'Restart PhishMailer\? Y/N': 7,  # 重启钓鱼工具的提示，可能用于循环钓鱼攻击
    r'pip install cryptography': 6,  # 自动安装依赖，可能用于隐藏钓鱼行为
    r'pip install requests': 6,  # 自动安装网络请求模块
    r'Mozilla/5\.0 \(X11; Linux x86_64\) AppleWebKit/537\.36 \(KHTML, like Gecko\)': 6,  # 常见的伪装User-Agent字符串
    r'__version__': 6,  # 程序版本信息，可能用于显示或伪装工具版本
    r'root': 7  # 提示需要root权限，可能用于执行高权限操作
}

def detect_patterns(code, patterns):
    """
    检测代码中是否包含指定的模式。
    """
    results = {}
    for pattern, score in patterns.items():
        if re.search(pattern, code):
            results[pattern] = score
    return results

def main(file_path):
    """
    主函数，读取待检测文件，进行代码检测，并生成报告。
    """
    # 读取待检测的代码文件内容
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return

    # 检测字符串模式
    string_results = detect_patterns(code, string_patterns)

    # 生成和打印报告
    report = []
    for pattern, score in string_results.items():
        report.append(f"Detected pattern: '{pattern}' with score {score}")

    print('\n'.join(report))

if __name__ == "__main__":
    # 指定待检测的代码文件路径
    # 在实际运行中，替换为你要检测的文件路径
    target_file_path = r"D:\AAAshuju\PycharmProjects\Detector\Trojan-Detector\src\Python\src_zys\Trojan\main.py"
    main(target_file_path)
