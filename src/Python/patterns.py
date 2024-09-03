#僵尸网络特征
botnet_patterns_scores = {
    "imports": {
        "from Crypto import Random": 6,  # 用于生成随机数，通常用于加密通信。
        "from Crypto.Cipher import AES": 7,  # AES加密模块，常用于加密数据以隐藏恶意行为。
        "import bitcoinrpc": 8,  # 与比特币RPC通信相关的库，可能用于管理或交易比特币，这在僵尸网络中较为典型。
        "import wmi": 7,  # 用于与Windows Management Instrumentation（WMI）进行交互，可用于监视和控制Windows系统的进程等。
        "import ssl": 6,  # 用于SSL/TLS加密，确保网络通信的安全性，这是僵尸网络中用于保护通信的技术。
        "import win32com.shell.shell as shell": 8,  # 用于提升权限和执行特权命令，这是恶意软件常用的技术。
        "import _thread": 6,  # 用于创建新线程以并发执行任务，常见于恶意软件用于并发处理。
        "import signal": 6,  # 信号处理库，用于捕捉和处理系统信号，常见于恶意软件的持久化机制。
        "import platform": 5,  # 用于获取操作系统信息，常见于恶意软件中用于系统环境识别。
        "import urllib.request": 5  # 用于处理URL请求，可能用于下载或上传恶意文件。
    },
    "function_calls": {
        "base64.b64encode": 7,  # 使用Base64编码，通常用于隐藏加密后的数据。
        "base64.b64decode": 7,  # 使用Base64解码，恢复加密后的数据。
        "wmi.WMI": 8,  # 通过WMI接口与Windows系统进行交互，用于监控和控制系统进程。
        "bitcoinrpc.connect_to_remote": 8,  # 连接远程比特币节点，可能用于比特币交易管理。
        "ssl.wrap_socket": 7,  # 使用SSL/TTLS包装套接字，确保网络通信的安全性，通常用于保护恶意通信不被检测。
        "socksocket.connect": 9,  # 通过SOCKS代理连接目标地址，通常用于隐藏通信或绕过防火墙。
        "socksocket.setproxy": 9,  # 设置SOCKS代理服务器，通常用于隐藏通信或规避网络监控。
        "socksocket.__negotiatesocks5": 9,  # 进行SOCKS5协商，设置代理连接，这是隐藏通信的关键部分。
        "socksocket.__negotiatesocks4": 9,  # 进行SOCKS4协商，类似于SOCKS5，但支持的功能较少，仍用于隐藏通信。
        "socksocket.__negotiatehttp": 9,  # 通过HTTP代理协商连接，另一种隐藏网络流量的手段。
        "signal.signal": 7,  # 注册信号处理程序，确保恶意软件在特定信号下执行特定操作或忽略系统的终止信号。
        "irc.send": 8,  # 用于通过IRC协议发送数据，控制僵尸网络中的受感染机器。
        "irc.recv": 8,  # 用于接收IRC协议的数据，监听来自控制服务器的命令。
        "create_socket": 8,  # 创建IRC套接字连接，通常用于连接控制服务器。
        "connect_to": 8,  # 连接到指定的服务器地址，通常用于建立与C&C服务器的通信。
        "join_channels": 8,  # 加入指定的IRC频道，等待或发送控制命令。
        "quit_bot": 8,  # 发送QUIT命令，可能用于断开与IRC服务器的连接，或在完成恶意任务后退出。
        "parse": 8,  # 解析IRC消息，提取发送者、指令和目标信息，用于后续指令处理。
        "privmsg": 8,  # 发送私信命令，可能用于向特定用户或频道发送命令结果或状态信息。
        "pong": 7,  # 用于响应PING请求，保持与服务器的连接活跃。
        "platform.uname": 6,  # 获取系统基本信息，如操作系统、主机名、版本等，常用于环境侦察。
        "requests.get": 6,  # 发送HTTP GET请求，可能用于从C&C服务器获取指令或下载文件。
        "urllib.request.urlretrieve": 6,  # 下载文件，常用于将恶意软件或配置文件从远程服务器拉取到受感染机器。
        "subprocess.Popen": 8,  # 执行系统命令，常用于执行恶意操作，如启动攻击或修改系统配置。
        "os.path.isfile": 6,  # 检查文件是否存在，常用于确认恶意文件或配置文件已成功下载或修改。
        "time.sleep": 6  # 延迟执行，通常用于规避检测或控制执行节奏。
    },
    "strings": {
        "nircmd": 6,  # 第三方命令行工具，可能用于修改文件属性或执行其他系统操作。
        "echo y | del": 7,  # 删除文件命令，用于清理痕迹。
        "rpc_user": 8,  # 比特币RPC用户名，表明与比特币相关的操作。
        "rpc_password": 8,  # 比特币RPC密码，涉及与比特币节点的身份验证。
        "RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$RUSSIA!@#$": 9,  # 用作IRC密码的字符串，具有高度定制性，表明IRC通信。
        "f4eqxs3tyrkba7f2.onion": 9,  # TOR网络的.onion地址，常用于隐藏通信。
        "SOCKS5": 8,  # 与代理设置和网络流量隐藏有关的关键字。
        "CONNECT": 8,  # HTTP代理中的CONNECT方法，用于隧道化网络连接。
        "kill bot": 7,  # 用于终止恶意软件的命令，可能用于逃避检测或清理痕迹。
        "VSE": 7,  # 表示Valve Source Engine Query攻击的命令。
        "STD": 7,  # 表示使用随机垃圾字符串进行的UDP Flood攻击命令。
        "irc.freenode.net": 8,  # IRC服务器地址，常用于僵尸网络的控制通信。
        "6667": 7,  # IRC默认端口号，通常用于未加密的IRC通信。
        "##evilxyz": 8,  # IRC频道名，可能用于聚合僵尸网络的受控机器。
        "PRIVMSG": 8,  # IRC协议中的私信命令，常用于发送控制命令或报告结果。
        "QUIT": 8,  # IRC协议中的QUIT命令，用于断开与服务器的连接。
        "Nickname is already in use": 7,  # IRC服务器的响应，表明昵称已被占用，可能触发更换昵称的操作。
        "http://freegeoip.net/json/": 7,  # 用于获取地理位置信息，可能用于针对性攻击或环境识别。
        "cmd.exe": 7,  # Windows命令行解释器，可能用于执行系统命令。
        "C:\\Windows\\system32\\cmd.exe": 7,  # Windows系统路径，可能用于执行恶意命令或脚本。
        "awesome.exe": 8,  # 恶意软件自我更新或替换后的文件名，常用于隐匿其真实用途。
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": 8  # 注册表路径，常用于设置开机自启动。
    }
}


# 渗透测试的特征模式
penetrationTesting_patterns = {
    "imports": {
        "mechanize": 7,  # 自动化web浏览器操作，常用于XSS、CSRF、SQL注入等攻击测试，但也可能用于自动化测试和爬虫
        "paramiko": 6,  # SSH连接库，常用于SSH暴力破解和远程访问攻击，也可能用于合法的远程管理
        "metasploit.msfrpc": 9,  # Metasploit的RPC客户端，用于与Metasploit框架进行交互，主要用于渗透测试
        "metasploit.msfconsole": 9,  # Metasploit控制台，常用于执行Metasploit模块，主要用于渗透测试
        "nmap": 7,  # Nmap扫描器，用于端口扫描和服务发现，虽然用于渗透测试，但也可能用于网络管理
        "zapv2": 6,  # OWASP ZAP的Python接口，用于Web应用程序安全扫描，可能用于合法的安全测试
        "w3af_api_client": 6,  # w3af的API客户端，用于Web应用程序安全扫描和渗透测试
    },
    "function_calls": {
        "MsfRpcClient": 9,  # 创建Metasploit RPC客户端，常用于与Metasploit框架交互，渗透测试专用
        "MsfRpcConsole.execute": 9,  # 在Metasploit控制台执行命令，用于执行漏洞利用模块，渗透测试专用
        "nmap.PortScanner.scan": 7,  # 使用Nmap进行端口扫描，虽然用于渗透测试，但也可能用于网络管理
        "ZAPv2.spider.scan": 6,  # OWASP ZAP的蜘蛛扫描，用于Web爬虫和安全测试，可能用于合法的安全测试
        "ZAPv2.ascan.scan": 6,  # OWASP ZAP的主动扫描，用于发现Web应用程序漏洞，可能用于合法的安全测试
        "paramiko.SSHClient.connect": 7,  # 尝试SSH连接，常用于暴力破解攻击，也可能用于合法的远程管理
        "Scan.start": 6,  # 使用w3af API客户端启动扫描，主要用于Web应用程序渗透测试
    },
    "strings": {
        "brute force": 8,  # 暴力破解，渗透测试中常见的攻击方式
        "SQL Injection": 9,  # SQL注入攻击，常见的攻击向量，渗透测试专用
        "exploit": 9,  # 利用漏洞，明确表明攻击意图
        "reverse shell": 9,  # 反向Shell，常见的攻击手段
        "Password found": 9,  # 密码发现提示，通常在暴力破解工具中出现
        "RHOSTS": 8,  # 远程主机，通常在Metasploit和其他渗透测试工具中用于指定攻击目标
        "Connected successfully": 7,  # 连接成功提示，用于暴力破解攻击，也可能用于合法的网络连接测试
    }
}

# 代码混淆的特征模式
obfuscation_patterns = {
    "imports": {
        "distorm3": 9,  # 用于反汇编，不常见于正常代码，可能用于底层操作或代码混淆
        "marshal": 8,  # 用于序列化对象为字节码，可能隐藏或混淆代码
        "importlib": 6,  # 动态导入模块，可能用于加载恶意模块或隐藏模块的实际用途
        "codecs": 5,  # 处理字符编码，可能在混淆过程中操纵字符串
        "secrets": 7  # 生成加密强度的随机数，可能用于生成难以预测的随机字符串或数据
    },
    "function_calls": {
        "eval": 9,  # 执行字符串形式的代码，混淆和恶意代码常见
        "exec": 8,  # 动态执行代码片段，恶意代码中常用
        "compile": 7,  # 将字符串编译为字节码并执行，增加混淆难度
        "importlib.import_module": 6,  # 动态导入模块，可能用于加载恶意模块
        "subprocess.check_output": 7,  # 执行系统命令并获取输出，可能用于隐藏执行命令
        "codecs.open": 5  # 以特定编码打开文件，可能在混淆中处理非标准编码数据
    },
    "strings": {
    "AMSI_RESULT_NOT_DETECTED": 10,  # 绕过AMSI的标志字符串，恶意代码常见
    "scramble": 9,  # 混淆字符串的标志，恶意混淆代码中常见
    "unscramble": 9,  # 解混淆字符串的标志，恶意混淆代码中常见
    "-join(({','.join([str(int(b)) for b in self.content.encode()])})|%{{[char]$_}});": 10,  # 隐藏或加密命令的PowerShell代码片段
    "rot13": 9,  # 一种简单的字母替换加密，在混淆代码中较常见，用于简单的文字混淆
    "hexlify": 8,  # 将数据编码为十六进制表示，在混淆代码中用于隐藏字符串内容
    "unhexlify": 8,  # 将十六进制数据解码回原始数据，通常与hexlify配合使用，用于解混淆
    "xor": 9,  # 用于XOR操作，通常用于混淆数据或简单加密，恶意代码中常见
    "RC4": 8,  # 一种流密码算法，在混淆代码中用于加密数据，恶意代码中较常见
    "obfuscate": 9,  # 明示的“混淆”操作，几乎只出现在混淆工具或恶意代码中
    "decrypt": 8,  # 解密操作，通常与混淆手段有关，可能在恶意代码中用于解密被隐藏的数据
    #"exec('".format(...)": 9,  # 动态执行代码的格式化字符串，几乎只出现在混淆或恶意代码中
    "reverse": 7,  # 字符串反转操作，用于简单的混淆，正常代码中较少见
    "random.choice": 7,  # 用于生成随机选择，可能在混淆代码中用于生成随机变量名或数据
    }
}

# 钓鱼软件的特征模式
PhishingAttack_patterns_scores = {
    "Import": {
        "bs4.BeautifulSoup": 8,  # 通常用于解析HTML，可能用于从钓鱼页面中提取表单或其他信息
        "urllib2": 7,  # 用于发起网络请求，可能用于发送钓鱼数据
        "SimpleHTTPServer": 8,  # 构建简单的HTTP服务器，用于托管钓鱼页面
        "SocketServer": 8,  # 处理网络连接，可能用于管理多个钓鱼目标的连接
        "cgi": 8,  # 处理HTTP请求中的表单数据，可能用于收集钓鱼页面上的用户输入
        "requests": 6,  # 用于发送HTTP请求，可能被用来发送钓鱼信息或获取恶意内容
        "cryptography": 7,  # 加密模块，可能用于加密敏感信息
        "msal": 8,  # Microsoft身份验证库，可能被用来进行恶意身份验证或获取访问令牌
        "hashlib": 6,  # 用于生成文件的哈希值，可能用于检查或操纵文件的完整性
        "shutil": 6,  # 文件操作模块，可能用于移动或复制恶意文件
    },
    
    "Function Calls": {
        "opener.open()": 8,  # 发送网络请求，可能用于上传钓鱼数据
        "handler.do_POST()": 8,  # 处理HTTP POST请求，可能用于接收钓鱼表单中的数据
        "BeautifulSoup()": 8,  # 解析HTML页面，提取敏感用户信息
        "server_version": 7,  # 用于设置服务器版本信息，可能伪装成合法服务
        "Instagram()": 8,  # 钓鱼邮件模板调用，具体社交平台或服务的钓鱼攻击
        "Twitter()": 8,  # 钓鱼邮件模板调用
        "MailPick()": 7,  # 用户选择钓鱼目标
        "RedirectBypass()": 8,  # 重定向绕过功能，可能用于掩盖钓鱼攻击
        "MailerMenu()": 8,  # 调用邮件发送菜单，可能用于钓鱼邮件的管理和发送
        "CurrentDir()": 7,  # 获取当前目录，通常用于确定保存钓鱼模板的位置
        "sys.exit()": 6,  # 终止程序，可能在检测到不适合的Python版本或其他异常情况下调用
        "exec(base64.b64decode())": 8,  # 执行base64解码后的代码，通常用于隐藏恶意代码
        "PublicClientApplication()": 8,  # 初始化MSAL客户端，可能用于获取访问令牌进行钓鱼攻击
        "hashFile()": 7,  # 生成文件的MD5、SHA1、SHA256哈希值，可能用于文件完整性校验或攻击
        "p_success()": 6,  # 打印成功信息，可能用于美化或混淆输出
        "getTenantID()": 7,  # 通过用户名获取Tenant ID，可能用于目标识别
        "randomword()": 6,  # 生成随机字符串，可能用于创建伪装的文件名
        "urlretrieve()": 6,  # 下载文件，可能用于获取恶意执行文件
        "raw_input()": 6,  # 获取用户输入，可能用于接受恶意文件的URL或其他信息
        "os.rename()": 6,  # 重命名文件，可能用于伪装恶意文件
        "exec_com()": 7,  # 执行外部命令，可能用于更新或安装恶意组件
    },
    
    "Strings": {
        "User-Agent": 6,  # 可能用于伪装成合法用户或爬虫
        "Weeman": 8,  # 钓鱼工具的名称，可能在恶意代码中出现
        "action_url": 7,  # 可能是钓鱼表单的提交目标
        "Please install beautifulsoup 4": 7,  # 工具依赖的提示信息
        "clone()": 8,  # 可能用于克隆合法网站以进行钓鱼
        "history.log": 7,  # 日志文件，可能用于记录钓鱼数据
        "root@phishmailer:~": 8,  # 钓鱼工具的提示符，可能用于引导用户进行恶意操作
        "Your Templates Will Be Saved Here": 7,  # 钓鱼模板保存路径的提示
        "Phish": 9,  # 明示钓鱼意图的字符串
        "Restart PhishMailer? Y/N": 7,  # 重启钓鱼工具的提示，可能用于循环钓鱼攻击
        "pip install cryptography": 6,  # 自动安装依赖，可能用于隐藏钓鱼行为
        "pip install requests": 6,  # 自动安装网络请求模块
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)": 6,  # 常见的伪装User-Agent字符串
        "__version__": 6,  # 程序版本信息，可能用于显示或伪装工具版本
        "root": 7,  # 提示需要root权限，可能用于执行高权限操作
    }
}

# 病毒的特征模式
malware_patterns = {
    "imports": {
        "paramiko": 9,  # SSH连接库，常用于蠕虫和远程控制工具
        "scp": 8,  # SCP文件传输库，常见于恶意软件传播
        "PySide2.QtWidgets": 6,  # GUI库，可能用于恶意弹窗或假冒界面
        "cached_property": 4  # 用于缓存恶意数据，较少在正常代码中使用
    },
    "functions": {
        "exec": 9,  # 动态执行代码，恶意代码常用
        "eval": 9,  # 动态执行表达式，恶意行为标志
        "paramiko.SSHClient.connect": 8,  # 恶意传播中的SSH连接
        "scp.SCPClient.put": 7,  # 用于恶意文件上传
        "scp.SCPClient.get": 7,  # 用于恶意文件或数据下载
        "open('malware.py', 'wb')": 8  # 写入恶意代码文件的行为
    },
    "strings": {
        "INJECTION SIGNATURE": 9,  # 恶意代码注入标志
        "malware": 9,  # 明确表示恶意软件的关键字
        "infect": 8,  # 感染行为描述
        "dropper": 7,  # 载荷投递的恶意软件
        "payload": 7,  # 恶意载荷标识
        "command and control": 8,  # 恶意软件的C2服务器控制
        "keylogger": 8,  # 键盘记录器行为
        "ransom": 8,  # 勒索软件相关标志
        "passwords.txt": 7,  # 密码窃取行为的文件名
        "send to server": 8  # 数据发送到攻击者服务器的行为
    }
}

# 道德黑客的特征模式
ethicalHacking_patterns = {
    "imports": {
        "scapy.all": 9,  # Scapy是一个强大的网络包生成和嗅探库，常用于网络攻击和渗透测试
        "dpkt": 8,  # 用于处理网络数据包，常用于数据包分析和网络攻击
        "pynput": 8,  # 用于捕捉键盘输入，常用于键盘记录器（keylogger）工具
    },
    "function_calls": {
        "scapy.all.ARP": 9,  # 创建ARP包，用于ARP欺骗攻击
        "scapy.all.send": 8,  # 发送网络包，常用于各种网络攻击
        "scapy.all.sniff": 9,  # 嗅探网络流量，常用于网络嗅探和攻击
        "dpkt.ethernet.Ethernet": 8,  # 用于解析以太网帧，常用于数据包分析工具
        "dpkt.ip.IP": 8,  # 用于解析IP数据包，常用于数据包分析和攻击
        "dpkt.tcp.TCP": 8,  # 用于解析TCP数据包，常用于数据包分析和攻击
        "pynput.keyboard.Listener": 8,  # 监听键盘输入，常用于键盘记录器
        "retrieveBanner": 7,  # 获取服务的Banner信息，可能用于漏洞扫描或服务识别
        "checkVulnerabilities": 8,  # 检查Banner中的漏洞信息，常见于漏洞扫描工具
        "returnBanner": 7,  # 获取服务的Banner信息，类似于前述的retrieveBanner函数，常用于服务识别
    },
    "strings": {
        "ARP spoofing": 9,  # ARP欺骗攻击，常见的网络攻击方式
        "Packet sniffing": 8,  # 数据包嗅探，常用于网络流量分析和攻击
        "SYN flood": 9,  # SYN洪水攻击，常见的拒绝服务攻击手段
        "Spoofed IP": 8,  # 伪造的IP地址，常见于网络攻击
        "Keylogger": 9,  # 键盘记录器，常见的恶意软件或间谍软件功能
        "Reverse shell": 9,  # 反向Shell，常见的远程访问和控制工具
        "Server has vulnerability": 8,  # 检测到服务器存在漏洞，常见于漏洞扫描工具
        "Scanning": 7,  # 扫描操作，可能用于端口扫描或漏洞扫描
        "Enter Target IP to Scan": 7,  # 目标IP输入提示，常见于扫描工具
    }
}

# 加密器的特征模式
cryption_patterns={
    "Imports": {
        "winreg": 7,  # 用于与Windows注册表交互，加密器中可能用于持久化
        "win32event": 7,  # 用于系统同步对象的管理，加密器中可能用于确保单实例运行
        "ctypes": 8,  # 用于与C库交互，加密器中可能用于检测虚拟机或执行系统操作
        "subprocess": 7,  # 用于执行系统命令，加密器中可能用于操作控制
        "uuid": 6,  # 用于生成和处理UUID，加密器中可能用于设备识别或检测虚拟机环境
    },
    "Function_Calls": {
        "win32file.GetDriveType": 6,  # 检查驱动器类型，可能用于加密器识别加密目标
        "win32api.GetLogicalDriveStrings": 6,  # 获取逻辑驱动器列表，可能用于加密器识别加密目标
        "AES.new": 7,  # 创建AES加密对象，加密器中用于文件加密
        "RSA.generate": 7,  # 生成RSA密钥对，可能用于加密对称密钥，加密器中常见
        "RSA.importKey": 7,  # 导入公钥或私钥，加密器中常见，用于密钥管理
        "winreg.CreateKeyEx": 8,  # 创建注册表键，可能用于加密器的持久化操作
        "winreg.SetValueEx": 8,  # 设置注册表值，可能用于加密器的持久化操作
        "winreg.OpenKeyEx": 7,  # 打开注册表键，可能用于读取或修改加密器的持久化信息
        "winreg.DeleteValue": 7,  # 删除注册表值，可能用于清理加密器的痕迹
        "win32event.CreateMutex": 8,  # 创建系统Mutex对象，加密器中可能用于确保单一实例运行
        "Popen": 7,  # 执行系统命令，加密器中可能用于控制操作或执行加密命令
        "Popen.communicate": 6,  # 与子进程通信并获取输出结果，加密器中可能用于执行和监控命令
        "base64.b64encode": 7,  # 编码为Base64格式，加密器中可能用于混淆加密数据
        "base64.b64decode": 7,  # 解码Base64格式，加密器中可能用于解码和执行隐藏的加密代码
        "ctypes.cdll.LoadLibrary": 8,  # 加载DLL，加密器中可能用于执行特定系统操作或检测虚拟机环境
        "uuid.getnode": 6,  # 获取MAC地址，加密器中可能用于识别设备或检测虚拟机环境
    },
    "Strings": {
        "REGISTRY_LOCATION": 8,  # 注册表位置字符串，加密器可能用于存储配置信息或持久化
        "STARTUP_REGISTRY_LOCATION": 8,  # 注册表启动项位置，加密器中常用于持久化操作
        "GUI_LABEL_TEXT_FLASHING_ENCRYPTED": 9,  # 显示“文件已加密”的提示，加密器中特有
        "BTC_BUTTON_URL": 8,  # 比特币相关URL，加密器中可能用于引导用户支付
        "key.txt": 7,  # 密钥存储文件名，加密器中可能用于存储加密密钥
        "C3C9BF85E96BC3489996280489C1EE24": 7,  # 密钥字符串，加密器中常见，用于加密管理
        "vssadmin Delete Shadows /All /Quiet": 9,  # 删除卷影副本命令，加密器中可能用于防止数据恢复
        "encrypted_files.txt": 7,  # 加密文件列表文件名，加密器中可能用于记录加密文件
        "Encryption test": 7,  # 测试加密和解密功能的字符串，加密器中常见
        "Incorrect Decryption Key!": 8,  # 错误的解密密钥提示信息，加密器中特有
        "YOUR FILES HAVE BEEN ENCRYPTED!": 9,  # 勒索提示字符串，加密器中特有
        "TIME REMAINING": 8,  # 剩余时间显示字符串，加密器中常用于提示支付截止时间
        "WALLET ADDRESS:": 8,  # 比特币钱包地址字符串，加密器中常用于提示支付地址
        "BITCOIN FEE": 8,  # 比特币支付金额字符串，加密器中常用于提示支付金额
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 7,  # 示例比特币钱包地址，加密器中可能用于支付
        "AES Decryption Key": 8,  # AES解密密钥字符串，加密器中特有
        "mutex_rr_windows": 8,  # Mutex名称字符串，加密器中常用于确保单实例运行
        "The file is corrupt and cannot be opened": 7,  # 错误消息，加密器中可能用于防止多个实例运行
        "VMware Registry Detected": 8,  # 检测虚拟机注册表项的提示信息，加密器中特有
        "VMwareService.exe & VMwareTray.exe process are running": 8,  # 检测虚拟机相关进程的提示信息，加密器中特有
        "VMware MAC Address Detected": 8,  # 检测虚拟机MAC地址的提示信息，加密器中特有
        "exec(base64.b64decode(": 9,  # 恶意代码模式，使用Base64编码隐藏代码，加密器中特有
        "Cracking Speed on RunTime": 7,  # 显示暴力破解速度的提示信息，加密器中可能用于恐吓用户
    }
}
# 勒索软件的特征模式ransomware_patterns


# 防御绕过的特征模式Defense_Bypass_patterns


# 键盘记录器的特征模式Keyboard_patterns


# 后门的特征模式backdoor，exploit - 漏洞利用