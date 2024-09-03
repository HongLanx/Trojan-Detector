''' botnet - 僵尸网络
    phishing - 钓鱼攻击
    crypter - 加密器
    payload - 载荷
    防御绕过Defense_Bypass_patterns
    键盘记录器Keyboard_patterns
'''
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

#钓鱼软件特征
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

#勒索软件特征
cryption_patterns={
    "Imports": {
        "win32api": 6,  # 用于与Windows API交互，勒索软件中常见，但在合法程序中也常见
        "Popen": 7,  # 用于执行外部命令，可能用于恶意操作，但在合法程序中也常见
        "Crypto.PublicKey.RSA": 6,  # 用于非对称加密，合法和恶意软件中都可能使用
        "Crypto.Cipher.AES": 7,  # 用于对称加密，合法和恶意软件中都可能使用
        "Crypto.Random": 6,  # 用于生成随机数，合法加密和恶意软件中都常见
        "winreg": 7,  # 用于与Windows注册表交互，常见于持久化操作，可能用于恶意持久化
        "threading": 6,  # 用于创建和管理线程，正常项目和恶意软件中都可能使用
        "win32event": 7,  # 用于系统同步对象的管理，恶意软件中可能用于确保单实例运行
        "winerror": 6,  # 用于处理Windows错误代码，恶意软件中可能用于错误处理
        "hashlib": 6,  # 用于生成哈希值，常见于安全相关操作和恶意软件中
        "base64": 7,  # 用于Base64编码，可能用于混淆代码，在恶意软件中较为常见
        "ctypes": 8,  # 用于与C库交互，恶意软件中可能用于检测虚拟机或沙箱环境
        "subprocess": 7,  # 用于执行系统命令，恶意软件中可能用于执行危险操作
        "re": 5,  # 用于处理正则表达式，正常项目中常见
        "uuid": 6,  # 用于生成和处理UUID，恶意软件中可能用于检测虚拟机环境
    },
    "Function_Calls": {
        "win32file.GetDriveType": 6,  # 检查驱动器类型，可能用于识别加密目标，恶意软件中较常见
        "win32api.GetLogicalDriveStrings": 6,  # 获取逻辑驱动器列表，可能用于识别加密目标，恶意软件中较常见
        "AES.new": 7,  # 创建AES加密对象，勒索软件中较常见，但也用于合法加密
        "RSA.generate": 7,  # 生成RSA密钥对，可能用于加密对称密钥，勒索软件中常见
        "RSA.importKey": 7,  # 导入公钥或私钥，勒索软件中常见，但合法加密软件也可能使用
        "self.pad": 6,  # 用于数据填充，满足加密算法要求，常见于加密操作中
        "self.unpad": 6,  # 移除数据块填充，恢复原始数据，常见于解密操作中
        "winreg.CreateKeyEx": 8,  # 创建注册表键，常用于持久化操作，恶意软件中常见
        "winreg.SetValueEx": 8,  # 设置注册表值，常用于持久化，恶意软件中常见
        "winreg.OpenKeyEx": 7,  # 打开注册表键，可能用于读取或删除注册表信息，恶意软件中常见
        "winreg.DeleteValue": 7,  # 删除注册表值，可能用于清理痕迹，恶意软件中常见
        "Thread.start": 6,  # 启动线程，正常项目和恶意软件中都可能使用
        "Thread.stop": 6,  # 停止线程，正常项目和恶意软件中都可能使用
        "win32event.CreateMutex": 8,  # 创建系统Mutex对象，恶意软件中常用于确保单一实例运行
        "win32api.GetLastError": 6,  # 获取最后一个系统错误代码，恶意软件中可能用于判断操作结果
        "Popen": 7,  # 执行系统命令，恶意软件中常用于执行危险操作
        "Popen.communicate": 6,  # 与子进程通信并获取输出结果，恶意软件中较常见
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

# 绕过攻击的特征
bypass_attack_patterns = {
    "Imports": {
        "import curlify": 6,  # 导入'curlify'库，用于生成cURL命令，可能用于绕过攻击
        "import secrets": 5,  # 使用'secrets'库生成随机数据，可能用于伪装请求
        "import base64": 6,  # 使用'base64'库编码数据，可能用于隐匿payload
        "import colorama": 4,  # 使用'colorama'库进行彩色输出，可能用于混淆和伪装输出信息
        "import tldextract": 5,  # 用于提取域名信息，可能用于特定域名攻击
        "import validators": 4,  # 用于验证URL的库，可能用于预处理攻击目标
        "import bottle": 5,  # 导入'bottle'框架，可能用于构建恶意Web服务
        "import flaresolverr_service": 7,  # 导入自定义服务模块，可能用于绕过反爬虫机制
        "import pyrogram": 7,  # 使用'pyrogram'库构建Telegram Bot，可能用于恶意Bot操作
        "import requests": 4,  # 导入'requests'库用于HTTP请求，可能用于发送恶意请求
        "from curl_cffi import requests as Nreq": 6,  # 使用'curl_cffi'库替代'requests'，可能用于绕过某些安全检测
        "from lxml import etree": 5,  # 使用'lxml'解析HTML/XML内容，可能用于数据提取和绕过
        "from cfscrape import create_scraper": 7,  # 使用'cfscrape'绕过Cloudflare的防护
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
        "requests.get": 4,  # 发起GET请求，可能用于探测和信息收集
        "os.environ.get": 3,  # 获取环境变量，可能用于动态修改攻击行为
        "Bottle.route": 5,  # 用于定义Web服务的路由，可能用于创建恶意接口
        "Bottle.run": 5,  # 启动Web服务，可能用于运行恶意服务器
        "pyrogram.Client": 6,  # 初始化并启动Telegram Bot，可能用于控制恶意Bot
        "remove": 4,  # 删除文件，可能用于清除痕迹
        "requests.get(url).text": 4,  # 发送HTTP GET请求并获取响应文本，可能用于获取敏感信息
        "argparse.ArgumentParser": 3,  # 创建命令行参数解析器，可能用于灵活配置攻击行为
        "makeHttpRequest": 6,  # 可能用于发送HTTP请求，绕过安全防护
        "replace": 4,  # 替换字符串，可能用于修改恶意URL或头部信息
        "getStatusCode": 5,  # 获取HTTP状态码，可能用于判断绕过成功与否
        "analyzeResponse": 5,  # 分析HTTP响应，可能用于判断绕过攻击的有效性
        "rplHeader": 6,  # 替换HTTP头部信息，可能用于伪造或修改请求头
        "payload = ''": 3,  # 空payload的使用，可能用于某些特殊攻击场景
        '"GET", url, data=payload, headers=headersList': 4,  # 使用GET请求发送payload
        "gen_payload = data_string": 5,  # 生成payload
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
