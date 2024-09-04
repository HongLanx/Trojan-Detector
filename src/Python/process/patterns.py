#僵尸网络特征
botnet_patterns = {
    "Imports": {
        "Random": 4,  # 用于生成随机数，通常用于加密通信。
        "AES": 5,  # AES加密模块，常用于加密数据以隐藏恶意行为。
        "bitcoinrpc": 8,  # 与比特币RPC通信相关的库，可能用于管理或交易比特币，这在僵尸网络中较为典型。
        "wmi": 7,  # 用于与Windows Management Instrumentation（WMI）进行交互，可用于监视和控制Windows系统的进程等。
        "ssl": 6,  # 用于SSL/TLS加密，确保网络通信的安全性，这是僵尸网络中用于保护通信的技术。
        "win32com.shell.shell": 8,  # 用于提升权限和执行特权命令，这是恶意软件常用的技术。
        "_thread": 6,  # 用于创建新线程以并发执行任务，常见于恶意软件用于并发处理。
        "urllib.request": 5,  # 用于处理URL请求，可能用于下载或上传恶意文件。
        "Crypto": 3  #加密相关
    },
    "Function_Calls": {
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
        "privmsg": 8,  # 发送私信命令，可能用于向特定用户或频道发送命令结果或状态信息。
        "pong": 7,  # 用于响应PING请求，保持与服务器的连接活跃。
        "platform.uname": 6,  # 获取系统基本信息，如操作系统、主机名、版本等，常用于环境侦察。
        "requests.get": 6,  # 发送HTTP GET请求，可能用于从C&C服务器获取指令或下载文件。
        "urllib.request.urlretrieve": 6,  # 下载文件，常用于将恶意软件或配置文件从远程服务器拉取到受感染机器。
        "subprocess.Popen": 8,  # 执行系统命令，常用于执行恶意操作，如启动攻击或修改系统配置。
        "os.path.isfile": 6,  # 检查文件是否存在，常用于确认恶意文件或配置文件已成功下载或修改。
        "time.sleep": 6  # 延迟执行，通常用于规避检测或控制执行节奏。
    },
    "Strings": {
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
        "cmd.exe": 7,  # Windows命令行解释器，可能用于执行系统命令。
        "C:\\Windows\\system32\\cmd.exe": 7,  # Windows系统路径，可能用于执行恶意命令或脚本。
        "awesome.exe": 8,  # 恶意软件自我更新或替换后的文件名，常用于隐匿其真实用途。
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": 8  # 注册表路径，常用于设置开机自启动。
    }
}


# 渗透测试的特征模式
penetrationTesting_patterns = {
    "Imports": {
        "mechanize": 7,  # 自动化web浏览器操作，常用于XSS、CSRF、SQL注入等攻击测试，但也可能用于自动化测试和爬虫
        "paramiko": 6,  # SSH连接库，常用于SSH暴力破解和远程访问攻击，也可能用于合法的远程管理
        "metasploit.msfrpc": 9,  # Metasploit的RPC客户端，用于与Metasploit框架进行交互，主要用于渗透测试
        "metasploit.msfconsole": 9,  # Metasploit控制台，常用于执行Metasploit模块，主要用于渗透测试
        "nmap": 7,  # Nmap扫描器，用于端口扫描和服务发现，虽然用于渗透测试，但也可能用于网络管理
        "zapv2": 6,  # OWASP ZAP的Python接口，用于Web应用程序安全扫描，可能用于合法的安全测试
        "w3af_api_client": 6,  # w3af的API客户端，用于Web应用程序安全扫描和渗透测试
    },
    "Function_Calls": {
        "MsfRpcClient": 9,  # 创建Metasploit RPC客户端，常用于与Metasploit框架交互，渗透测试专用
        "MsfRpcConsole.execute": 9,  # 在Metasploit控制台执行命令，用于执行漏洞利用模块，渗透测试专用
        "nmap.PortScanner.scan": 7,  # 使用Nmap进行端口扫描，虽然用于渗透测试，但也可能用于网络管理
        "ZAPv2.spider.scan": 6,  # OWASP ZAP的蜘蛛扫描，用于Web爬虫和安全测试，可能用于合法的安全测试
        "ZAPv2.ascan.scan": 6,  # OWASP ZAP的主动扫描，用于发现Web应用程序漏洞，可能用于合法的安全测试
        "paramiko.SSHClient.connect": 7,  # 尝试SSH连接，常用于暴力破解攻击，也可能用于合法的远程管理
        "Scan.start": 6,  # 使用w3af API客户端启动扫描，主要用于Web应用程序渗透测试
    },
    "Strings": {
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
    "Imports": {
        "distorm3": 9,  # 用于反汇编，不常见于正常代码，可能用于底层操作或代码混淆
        "marshal": 8,  # 用于序列化对象为字节码，可能隐藏或混淆代码
        "importlib": 6,  # 动态导入模块，可能用于加载恶意模块或隐藏模块的实际用途
        "codecs": 5,  # 处理字符编码，可能在混淆过程中操纵字符串
        "secrets": 7  # 生成加密强度的随机数，可能用于生成难以预测的随机字符串或数据
    },
    "Function_Calls": {
        "importlib.import_module": 6,  # 动态导入模块，可能用于加载恶意模块
        "subprocess.check_output": 7,  # 执行系统命令并获取输出，可能用于隐藏执行命令
        "codecs.open": 5  # 以特定编码打开文件，可能在混淆中处理非标准编码数据
    },
    "Strings": {
        "AMSI_RESULT_NOT_DETECTED": 10,  # 绕过AMSI的标志字符串，恶意代码常见
        "scramble": 9,  # 混淆字符串的标志，恶意混淆代码中常见
        "unscramble": 9,  # 解混淆字符串的标志，恶意混淆代码中常见
        "-join(({','.join([str(int(b)) for b in self.content.encode()])})|%{{[char]$_}});": 10,  # 隐藏或加密命令的PowerShell代码片段
        "rot13": 9,  # 一种简单的字母替换加密，在混淆代码中较常见，用于简单的文字混淆
        "hexlify": 8,  # 将数据编码为十六进制表示，在混淆代码中用于隐藏字符串内容
        "unhexlify": 8,  # 将十六进制数据解码回原始数据，通常与hexlify配合使用，用于解混淆
        "RC4": 8,  # 一种流密码算法，在混淆代码中用于加密数据，恶意代码中较常见
        "obfuscate": 9,  # 明示的“混淆”操作，几乎只出现在混淆工具或恶意代码中
        "decrypt": 8,  # 解密操作，通常与混淆手段有关，可能在恶意代码中用于解密被隐藏的数据
        "reverse": 7,  # 字符串反转操作，用于简单的混淆，正常代码中较少见
        "random.choice": 7,  # 用于生成随机选择，可能在混淆代码中用于生成随机变量名或数据
    }
}

# 钓鱼软件的特征模式
phishingAttack_patterns = {
    "Imports": {
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
    
    "Function_Calls": {
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
    }
}

# 病毒的特征模式
malware_patterns = {
    "Imports": {
        "paramiko": 9,  # SSH连接库，常用于蠕虫和远程控制工具
        "scp": 8,  # SCP文件传输库，常见于恶意软件传播
        "PySide2.QtWidgets": 6,  # GUI库，可能用于恶意弹窗或假冒界面
        "cached_property": 4,  # 用于缓存恶意数据，较少在正常代码中使用
        "trojan": 9 # 恶意软件的标识 
    },
    "Function_Calls": {
        "paramiko.SSHClient.connect": 8,  # 恶意传播中的SSH连接
        "scp.SCPClient.put": 7,  # 用于恶意文件上传
        "scp.SCPClient.get": 7,  # 用于恶意文件或数据下载
        "open('malware.py', 'wb')": 8  # 写入恶意代码文件的行为
    },
    "Strings": {
        "INJECTION SIGNATURE": 9,  # 恶意代码注入标志
        "malware": 9,  # 明确表示恶意软件的关键字
        "infect": 8,  # 感染行为描述
        "dropper": 7,  # 载荷投递的恶意软件
        "payload": 7,  # 恶意载荷标识
        "command and control": 8,  # 恶意软件的C2服务器控制
        "keylogger": 8,  # 键盘记录器行为
        "ransom": 8,  # 勒索软件相关标志
        "passwords.txt": 7,  # 密码窃取行为的文件名
        "send to server": 8,  # 数据发送到攻击者服务器的行为
        "trojan": 9 # 恶意软件的标识 
    }
}

# 道德黑客的特征模式
ethicalHacking_patterns = {
    "Imports": {
        "scapy.all": 9,  # Scapy是一个强大的网络包生成和嗅探库，常用于网络攻击和渗透测试
        "dpkt": 8,  # 用于处理网络数据包，常用于数据包分析和网络攻击
        "pynput": 8,  # 用于捕捉键盘输入，常用于键盘记录器（keylogger）工具
    },
    "Function_Calls": {
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
    "Strings": {
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

# 勒索软件的特征模式
ransomware_patterns={
    "Imports": {
        "win32api": 6,  # 用于与Windows API交互，勒索软件中常见，但在合法程序中也常见
        "win32file": 5,  # 用于文件操作，常见于合法文件操作和恶意软件中
        "Popen": 7,  # 用于执行外部命令，可能用于恶意操作，但在合法程序中也常见
        "Crypto.PublicKey.RSA": 6,  # 用于非对称加密，合法和恶意软件中都可能使用
        "Crypto.Cipher.AES": 7,  # 用于对称加密，合法和恶意软件中都可能使用
        "Crypto.Random": 6,  # 用于生成随机数，合法加密和恶意软件中都常见
        "winreg": 7,  # 用于与Windows注册表交互，常见于持久化操作，可能用于恶意持久化
        "win32event": 7,  # 用于系统同步对象的管理，恶意软件中可能用于确保单实例运行
        "winerror": 6,  # 用于处理Windows错误代码，恶意软件中可能用于错误处理
        "hashlib": 6,  # 用于生成哈希值，常见于安全相关操作和恶意软件中
        "base64": 7,  # 用于Base64编码，可能用于混淆代码，在恶意软件中较为常见
        "ctypes": 8,  # 用于与C库交互，恶意软件中可能用于检测虚拟机或沙箱环境
        "uuid": 6,  # 用于生成和处理UUID，恶意软件中可能用于检测虚拟机环境
    },
    "Function_Calls": {
        "win32file.GetDriveType": 6,  # 检查驱动器类型，可能用于识别加密目标，恶意软件中较常见
        "win32api.GetLogicalDriveStrings": 6,  # 获取逻辑驱动器列表，可能用于识别加密目标，恶意软件中较常见
        "is_optical_drive": 5,  # 自定义函数，结合GetDriveType使用，可能用于避免加密不必要的驱动器
        "AES.new": 7,  # 创建AES加密对象，勒索软件中较常见，但也用于合法加密
        "RSA.generate": 7,  # 生成RSA密钥对，可能用于加密对称密钥，勒索软件中常见
        "RSA.importKey": 7,  # 导入公钥或私钥，勒索软件中常见，但合法加密软件也可能使用
        "self.pad": 6,  # 用于数据填充，满足加密算法要求，常见于加密操作中
        "self.unpad": 6,  # 移除数据块填充，恢复原始数据，常见于解密操作中
        "winreg.CreateKeyEx": 8,  # 创建注册表键，常用于持久化操作，恶意软件中常见
        "winreg.SetValueEx": 8,  # 设置注册表值，常用于持久化，恶意软件中常见
        "winreg.OpenKeyEx": 7,  # 打开注册表键，可能用于读取或删除注册表信息，恶意软件中常见
        "winreg.DeleteValue": 7,  # 删除注册表值，可能用于清理痕迹，恶意软件中常见
        "os.remove": 5,  # 删除文件，正常项目和恶意软件中都可能使用
        "webbrowser.open": 5,  # 打开指定URL，正常项目和恶意软件中都可能使用
        "pub.subscribe": 4,  # 在GUI中订阅消息主题，正常项目中较为常见
        "Thread.start": 6,  # 启动线程，正常项目和恶意软件中都可能使用
        "Thread.stop": 6,  # 停止线程，正常项目和恶意软件中都可能使用
        "win32api.GetLastError": 6,  # 获取最后一个系统错误代码，恶意软件中可能用于判断操作结果
        "Popen": 7,  # 执行系统命令，恶意软件中常用于执行危险操作
        "Popen.communicate": 6,  # 与子进程通信并获取输出结果，恶意软件中较常见
        "traceback.format_tb": 5,  # 获取异常回溯信息，调试模式下常用，正常项目中较常见
        "hashlib.sha256": 6,  # 生成SHA-256哈希值，常见于加密操作和恶意软件中
        "base64.b64encode": 7,  # 编码为Base64格式，恶意软件中可能用于隐藏或混淆代码
        "base64.b64decode": 7,  # 解码Base64格式，恶意软件中可能用于执行隐藏代码
        "ctypes.cdll.LoadLibrary": 8,  # 加载DLL，恶意软件中可能用于检测沙箱或虚拟机环境
        "re.findall": 5,  # 查找匹配正则表达式的部分，正常项目中较为常见
        "uuid.getnode": 6,  # 获取MAC地址，恶意软件中可能用于检测虚拟机环境
    },
    "Strings": {
        "REGISTRY_LOCATION": 8,  # 注册表位置字符串，常用于存储恶意软件配置信息
        "STARTUP_REGISTRY_LOCATION": 8,  # 注册表启动项位置，常用于持久化操作
        "GUI_LABEL_TEXT_FLASHING_ENCRYPTED": 9,  # 显示“文件已加密”的提示，勒索软件中特有
        "BTC_BUTTON_URL": 8,  # 比特币相关URL，勒索软件中常见，用于支付赎金
        "key.txt": 7,  # 密钥存储文件名，勒索软件中可能使用
        "C3C9BF85E96BC3489996280489C1EE24": 7,  # 密钥字符串，常见于勒索软件的密钥管理流程
        "vssadmin Delete Shadows /All /Quiet": 9,  # 删除卷影副本命令，恶意软件中用于防止文件恢复
        "encrypted_files.txt": 7,  # 加密文件列表文件名，勒索软件中可能使用
        "Encryption test": 7,  # 测试加密和解密功能的字符串，勒索软件中常见
        "Incorrect Decryption Key!": 8,  # 错误的解密密钥提示信息，勒索软件中特有
        "gui_title": 5,  # GUI标题字符串，正常项目中较为常见
        "YOUR FILES HAVE BEEN ENCRYPTED!": 9,  # 勒索提示字符串，勒索软件中特有
        "TIME REMAINING": 8,  # 剩余时间显示字符串，勒索软件中常用于恐吓受害者
        "WALLET ADDRESS:": 8,  # 比特币钱包地址字符串，勒索软件中常见
        "BITCOIN FEE": 8,  # 比特币支付金额字符串，勒索软件中常见
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 7,  # 示例比特币钱包地址，勒索软件中常见
        "AES Decryption Key": 8,  # AES解密密钥字符串，勒索软件中特有
        "mutex_rr_windows": 8,  # Mutex名称字符串，常用于确保单实例运行
        "The file is corrupt and cannot be opened": 7,  # 错误消息，常用于防止多个实例运行
        "VMware Registry Detected": 8,  # 检测虚拟机注册表项的提示信息，恶意软件中特有
        "VMwareService.exe & VMwareTray.exe process are running": 8,  # 检测虚拟机相关进程的提示信息，恶意软件中特有
        "VMware MAC Address Detected": 8,  # 检测虚拟机MAC地址的提示信息，恶意软件中特有
        "exec(base64.b64decode(": 9,  # 恶意代码模式，使用Base64编码隐藏代码，勒索软件中特有
        "Cracking Speed on RunTime": 7,  # 显示暴力破解速度的提示信息，勒索软件中常见
    }
}


# 绕过攻击的特征模式
bypassAttack_patterns = {
    "Imports": {
        "curlify": 6,  # 导入'curlify'库，用于生成cURL命令，可能用于绕过攻击
        "secrets": 5,  # 使用'secrets'库生成随机数据，可能用于伪装请求
        "base64": 6,  # 使用'base64'库编码数据，可能用于隐匿payload
        "tldextract": 5,  # 用于提取域名信息，可能用于特定域名攻击
        "validators": 4,  # 用于验证URL的库，可能用于预处理攻击目标
        "bottle": 5,  # 导入'bottle'框架，可能用于构建恶意Web服务
        "flaresolverr_service": 7,  # 导入自定义服务模块，可能用于绕过反爬虫机制
        "pyrogram": 7,  # 使用'pyrogram'库构建Telegram Bot，可能用于恶意Bot操作
        "curl_cffi": 6,  # 使用'curl_cffi'库替代'requests'，可能用于绕过某些安全检测
        "lxml": 5,  # 使用'lxml'解析HTML/XML内容，可能用于数据提取和绕过
        "cfscrape": 7,  # 使用'cfscrape'绕过Cloudflare的防护
    },
    "Function_Calls": {
        "base64.b64encode": 6,  # 使用Base64编码数据，可能用于绕过WAF检测
        "secrets.token_hex": 5,  # 生成随机的十六进制token，可能用于伪造请求
        "urljoin": 4,  # 用于构造恶意URL
        "quote_plus(escape(": 4,  # 对URL中的数据进行编码，可能用于隐匿攻击
        "os.walk": 3,  # 遍历文件目录，可能用于查找和操作恶意文件
        "requests.request": 4,  # 直接发起HTTP请求，可能用于执行恶意操作
        "curlify.to_curl": 5,  # 将请求转换为cURL命令，可能用于重放或分析请求
        "tldextract.extract": 5,  # 提取域名信息，可能用于针对特定域名的攻击
        "validators.url": 4,  # 验证URL是否有效，可能用于筛选攻击目标
        "requests.post": 5,  # 发起POST请求，可能用于数据注入或其他恶意行为
        "os.environ.get": 3,  # 获取环境变量，可能用于动态修改攻击行为
        "Bottle.route": 5,  # 用于定义Web服务的路由，可能用于创建恶意接口
        "Bottle.run": 5,  # 启动Web服务，可能用于运行恶意服务器
        "pyrogram.Client": 6,  # 初始化并启动Telegram Bot，可能用于控制恶意Bot
        "requests.get(url).text": 4,  # 发送HTTP GET请求并获取响应文本，可能用于获取敏感信息
        "makeHttpRequest": 6,  # 可能用于发送HTTP请求，绕过安全防护
        "getStatusCode": 5,  # 获取HTTP状态码，可能用于判断绕过成功与否
        "analyzeResponse": 5,  # 分析HTTP响应，可能用于判断绕过攻击的有效性
        "rplHeader": 6,  # 替换HTTP头部信息，可能用于伪造或修改请求头
        '"GET", url, data=payload, headers=headersList': 4,  # 使用GET请求发送payload
        "response = client.post(url, data=gen_payload, headers=headers).json()": 6,  # 使用POST请求发送生成的payload
    },
    "Strings": {
        "User-Agent": 5,  # 伪装User-Agent头，可能用于绕过WAF
        "Referer": 5,  # 伪装Referer头，可能用于绕过安全策略
        "multipart/form-data": 5,  # 构造multipart请求，可能用于绕过WAF
        "application/json": 4,  # 伪装Content-Type为JSON，可能用于绕过检测
        "boundary": 5,  # 在multipart请求中设置自定义boundary，可能用于绕过防护
        "base64.b64encode(payload.encode('UTF-8'))": 6,  # 使用Base64编码payload，可能用于绕过检测
        "Replay with cURL:": 6,  # 提供cURL命令重放请求，可能用于攻击重现
        "X-Original-URL": 7,  # 使用自定义头部伪装URL，可能用于绕过服务器端检查
        "X-Custom-IP-Authorization": 7,  # 伪装IP头，可能用于绕过IP限制
        "localhost": 4,  # 使用localhost进行伪装，可能用于内部网络攻击
        "127.0.0.1": 4,  # 使用回环地址进行伪装，可能用于绕过外部安全措施
        "HEADLESS=false": 4,  # 禁用无头模式，可能用于模拟真实用户的行为
        "SSL_CERT_FILE": 4,  # 指定SSL证书文件，可能用于绕过SSL验证
        "__bypassing...__": 5,  # 显示绕过操作的提示信息，可能用于恶意活动
        "__generating...__": 5,  # 显示生成操作的提示信息，可能用于伪造请求
        "__jumping the wall...__": 6,  # 显示绕过防火墙的提示信息
    }
}


# 键盘记录器的特征模式Keyboard_patterns
keyboard_patterns = {
    "Imports": {
        "pynput": 6,         # 用于监听键盘和鼠标事件，键盘记录器常用
        "pyscreenshot": 7,   # 用于截屏，恶意软件中常用来获取屏幕内容
        "sounddevice": 6,    # 用于录音，可能被用于隐秘录音的恶意软件
        "pyHook": 9,         # 专门用于键盘和鼠标钩子管理，主要在键盘记录器中出现
        "pythoncom": 8,      # 与 pyHook 配合使用，通常用于键盘记录器
        "pyautogui": 6,      # 用于自动化控制鼠标键盘和截屏，恶意软件常用来获取屏幕内容
        "ImageGrab": 7,      # 用于截屏，恶意软件常用来获取屏幕内容
        "getpass": 6         # 用于获取用户信息，可能用于窃取用户凭证
    },
    "Function_Calls": {
        "pyHook.HookManager": 9,        # 管理键盘钩子，键盘记录器的关键函数
        "pythoncom.PumpMessages": 8,    # 保持键盘钩子工作，键盘记录器常用
        "win32console.GetConsoleWindow": 7,  # 获取并隐藏控制台窗口
        "win32gui.ShowWindow": 7,       # 隐藏窗口，恶意软件隐藏自身的常用方式
        "pyautogui.screenshot": 6,      # 截屏并保存，恶意软件获取屏幕内容
        "pynput.keyboard.Listener": 6,  # 键盘事件监听，常用于键盘记录器
        "pynput.mouse.Listener": 6,     # 鼠标事件监听，恶意监控工具中使用
        "pyscreenshot.grab": 7,         # 截取屏幕，用于恶意软件获取屏幕内容
        "sd.rec": 6,                    # 录音功能，隐秘录音的恶意软件常用
        "ImageGrab.grab": 7,            # 截屏功能，常用于恶意软件
        "getpass.getuser": 6            # 获取当前用户名，可能用于窃取用户信息
    },
    "Strings": {
        "KeyLogger Started...": 9,      # 标识键盘记录器启动，恶意软件常用
        "keyboardData": 8,              # 键盘记录数据的标识，常见于恶意软件
        "keylogs.txt": 9,               # 键盘记录文件名，恶意软件常用
        "New data from victim(Base64 encoded)": 9,  # 邮件内容中的恶意标识
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run": 7,  # 注册表路径，常用于恶意软件设置开机启动项
        "185.234.216.168": 10,          # 恶意IP地址，用于恶意服务器通信
        "185.92.220.60": 10,            # 恶意IP地址
        "82.146.35.40": 10,             # 恶意IP地址
        "94.102.49.193": 10,            # 恶意IP地址
        "185.100.87.72": 10,            # 恶意IP地址
        "malicious-domain.com": 10,     # 恶意域名
        "badactor.com": 10,             # 恶意域名
        "examplephishing.com": 10,      # 恶意域名
        "exploit-server.net": 10,       # 恶意域名
        "ransomware-site.org": 10,      # 恶意域名
        "logs-": 7,                     # 多个日志文件命名格式，通常用于窃取数据的恶意软件
        "C:\\Users\\Public\\Intel\\Logs": 8,  # 恶意软件用于存储窃取数据的路径
        "AdobePush.exe": 8              # 恶意软件自我复制的文件名
    }
}

# 漏洞利用的特征模式
exploit_patterns = {
    "Imports": {
        "shodan": 8,                     # 用于与Shodan API交互，通常在网络扫描或漏洞利用工具中使用
        "scapy.all": 9,                  # 用于网络数据包构建和发送，通常在网络攻击工具中使用
        "SimpleHTTPServer": 8,           # 简单HTTP服务器模块，用于构建恶意服务器
        "urllib2": 8,                    # 用于发送HTTP请求，常见于漏洞利用和攻击脚本中
    },
    "Function_Calls": {
        "shodan.Shodan": 8,                         # 用于访问Shodan API，通常在漏洞利用工具中使用
        "scapy.all.send": 9,                        # 用于发送构造的网络数据包，通常在网络攻击和漏洞利用中使用
        "Raw": 9,                                   # 构造原始负载数据，通常用于网络攻击
        "SimpleHTTPServer.SimpleHTTPRequestHandler": 8,  # 创建简单的HTTP请求处理程序，恶意服务器中常见
        "urllib2.urlopen": 8,                       # 发送HTTP请求，可能用于恶意数据的获取或命令执行
        "SocketServer.TCPServer": 8,                # 创建TCP服务器，恶意网络服务中常见
        "handler.serve_forever": 8,                 # 启动HTTP服务器，恶意服务器中常见
        "urllib.urlencode": 8,                      # 编码URL参数，常见于发送HTTP请求的恶意脚本中
        "urllib2.Request": 8,                       # 创建HTTP请求对象，常见于发送HTTP请求的恶意脚本中
    },
    "Strings": {
        "Shodan API Key": 7,                        # Shodan API Key相关的字符串，常见于利用Shodan进行漏洞扫描的工具中
        "bots.txt": 7,                              # 存储从Shodan获取的目标IP列表的文件名，通常在漏洞利用工具中出现
        "forged UDP packets": 9,                    # 伪造的UDP数据包，通常与DDoS攻击或网络攻击工具相关
        "XXE PoC exploit": 8,                       # 与XXE漏洞利用相关的描述，常见于漏洞利用工具中
        "exec(\"whoami\")": 8,                      # 常见于漏洞利用中的命令执行
        "<?php\n\tsystem($_GET[\"cmd\"]);": 9,      # PHP Webshell代码，用于远程命令执行的常见模式
        "/tmp/wgethack": 8,                         # 指定的恶意文件路径，可能用于检测恶意操作
        "WEBSHELL_URL": 8,                          # Webshell的URL，指向恶意脚本
        "Wget < 1.18 Access List Bypass / Race Condition PoC Exploit": 8,  # 与Wget漏洞利用相关的字符串，指向特定的恶意行为
        "CVE-2016-7098": 8,                         # 具体的CVE编号，指向已知的漏洞利用
        "malicious": 9,                             # 在恶意脚本中常见的标识词
        "Exploit": 9,                               # 通常用于描述恶意行为或漏洞利用的标识
        "reverse shell": 8,                         # 用于远程控制目标主机的技术，常见于漏洞利用中
        "PHPMailer": 8,                             # 电子邮件库名称，常见于相关的漏洞利用
        "SwiftMailer": 8,                           # 电子邮件库名称，常见于相关的漏洞利用
        "Zend Framework": 8,                        # PHP框架名称，常见于相关的漏洞利用
        "CVE-2016-10033": 8,                        # 具体的CVE编号，指向PHPMailer的漏洞利用
        "CVE-2016-10045": 8,                        # 具体的CVE编号，指向PHPMailer的漏洞利用
        "CVE-2016-10074": 8,                        # 具体的CVE编号，指向SwiftMailer的漏洞利用
        "CVE-2016-10034": 8,                        # 具体的CVE编号，指向Zend Framework的漏洞利用
        "Reverse Code Execution": 9,                # 表示远程代码执行的术语，常用于描述攻击目的
    }
}