''' botnet - 僵尸网络
    phishing - 钓鱼攻击
    crypter - 加密器
    payload - 载荷
'''
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
        "argparse": 5,  # 解析命令行参数，可能用于接受用户输入来执行钓鱼操作
        "hashlib": 6,  # 用于生成文件的哈希值，可能用于检查或操纵文件的完整性
        "random": 5,  # 生成随机字符串，可能用于创建伪装文件名或其他随机内容
        "sys": 5,  # 系统相关的功能，可能用于终止程序或输出消息
        "time": 5,  # 时间相关功能，可能用于延迟执行或记录时间
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