import re

def preprocess_code(code):
    """
    对代码进行预处理，去除注释和多余的空行。
    """
    # 去除 Python 代码中的单行注释
    code = re.sub(r'#.*', '', code)  # 去除单行注释
    
    # 去除 Python 代码中的多行注释（''' 或 """）
    code = re.sub(r'\'\'\'(.*?)\'\'\'', '', code, flags=re.DOTALL)  # 去除多行注释
    code = re.sub(r'\"\"\"(.*?)\"\"\"', '', code, flags=re.DOTALL)  # 去除多行注释
    
    # 去除多余的空行
    code = re.sub(r'\n\s*\n', '\n', code)
    
    return code

def find_suspicious_patterns(code):
    """
    在代码中查找可疑的模式。
    """
    # 定义正则表达式模式
    patterns = {
        r'from Crypto import Random': 6,
        r'from Crypto\.Cipher import AES': 7,
        r'import bitcoinrpc': 8,
        r'import wmi': 7,
        r'import ssl': 6,
        r'import win32com\.shell\.shell as shell': 8,
        r'import _thread': 6,
        r'import signal': 6,
        r'import platform': 5,
        r'import urllib\.request': 5,
        r'base64\.b64encode': 7,
        r'base64\.b64decode': 7,
        r'wmi\.WMI': 8,
        r'bitcoinrpc\.connect_to_remote': 8,
        r'ssl\.wrap_socket': 7,
        r'socksocket\.connect': 9,
        r'socksocket\.setproxy': 9,
        r'socksocket\.__negotiatesocks5': 9,
        r'socksocket\.__negotiatesocks4': 9,
        r'socksocket\.__negotiatehttp': 9,
        r'signal\.signal': 7,
        r'irc\.send': 8,
        r'irc\.recv': 8,
        r'create_socket': 8,
        r'connect_to': 8,
        r'join_channels': 8,
        r'quit_bot': 8,
        r'parse': 8,
        r'privmsg': 8,
        r'pong': 7,
        r'platform\.uname': 6,
        r'requests\.get': 6,
        r'urllib\.request\.urlretrieve': 6,
        r'subprocess\.Popen': 8,
        r'os\.path\.isfile': 6,
        r'time\.sleep': 6,
        r'nircmd': 6,
        r'echo y \| del': 7,
        r'rpc_user': 8,
        r'rpc_password': 8,
        r'RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$': 9,
        r'f4eqxs3tyrkba7f2\.onion': 9,
        r'SOCKS5': 8,
        r'CONNECT': 8,
        r'kill bot': 7,
        r'VSE': 7,
        r'STD': 7,
        r'irc\.freenode\.net': 8,
        r'6667': 7,
        r'##evilxyz': 8,
        r'PRIVMSG': 8,
        r'QUIT': 8,
        r'Nickname is already in use': 7,
        r'http://freegeoip\.net/json/': 7,
        r'cmd\.exe': 7,
        r'C:\\Windows\\system32\\cmd\.exe': 7,
        r'awesome\.exe': 8,
        r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': 8
    }

    

    # 查找所有模式
    results = {key: pattern.findall(code) for key, pattern in patterns.items()}
    return results

def generate_report(results):
    """
    根据检测结果生成报告。
    """
    report = []
    
    # 生成报告内容
    for pattern_name, matches in results.items():
        if matches:
            report.append(f"Detected {pattern_name}:")
            for match in matches:
                report.append(f"  {match}")
    
    return '\n'.join(report)

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

    # 预处理代码
    preprocessed_code = preprocess_code(code)

    # 查找可疑模式
    suspicious_patterns = find_suspicious_patterns(preprocessed_code)

    # 生成报告
    report = generate_report(suspicious_patterns)
    
    # 打印报告
    print(report)

if __name__ == "__main__":
    # 指定待检测的代码文件路径
    # 在实际运行中，替换为你要检测的文件路径
    target_file_path = 'main.py'
    main(target_file_path)
