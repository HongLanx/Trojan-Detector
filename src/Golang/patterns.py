# 加密器的特征模式
encryption_patterns = {
    "Imports": {
        "github.com/EvilBytecode/GolangStyle/pkg": 9,  # 非常特殊，一般不出现在正常代码中
        "crypto/aes": 5,  # 加密库，可用于正常和恶意代码
        "crypto/cipher": 5,  # 加密库，可用于正常和恶意代码
        "crypto/rc4": 7,  # RC4较少用于新的正常项目，但在老项目和恶意代码中见
        "crypto/sha1": 4,  # 虽然SHA-1已不再推荐使用，但仍广泛存在于许多代码中
        "golang.org/x/crypto/pbkdf2": 6  # 密码派生，通常用于安全需求高的场合

    },
    "FunctionCalls": {
        "base64.StdEncoding.EncodeToString": 3,  # 编码操作，广泛用途
        "syscall.Syscall": 6,  # 系统调用，可能用于特定操作，但在恶意代码中更常见
        "syscall.Write": 5,  # 系统级写操作，可用于多种场景
        "syscall.Exec": 7,  # 执行新程序，常见于恶意行为
        "syscall.Dup2": 7,  # 文件描述符操作，常见于需要控制文件输出的场景
        "rc4.NewCipher": 7,  # RC4加密实例化，较少用于新的正规项目
        "encoder.XORKeyStream": 8,  # 加密数据流，通常不出现在普通软件中
        "decoder.XORKeyStream": 8,  # 解密数据流，同上
        "pbkdf2.Key": 6,  # 密钥生成，通常用于需要强加密的场景
        "aes.NewCipher": 5,  # AES加密实例化，加密需求普遍
        "cipher.NewCFBEncrypter": 6,  # 加密器实例化，较特殊但有合法使用
        "cipher.NewCFBDecrypter": 6,  # 解密器实例化，较特殊但有合法使用
    },
    "Strings": {
        "secret": 7,  # 密钥相关，较敏感
        "encrypt": 6,  # 加密相关，有合法和非法使用
        "AES": 5,  # 加密标准，广泛使用
        "/proc/self/fd/": 8,  # 系统内部路径，可能用于隐藏进程信息
        "iv": 5,  # 初始化向量，加密过程中常用
        "salt": 7,  # 密码盐值，敏感度较高
        "RSA": 7,  # 非对称加密标准，用于加密和签名，较特殊但有合法用途
        "token": 6,  # 常用于认证和安全操作，具有较高的敏感度
        "cipher": 6,  # 指加密算法或加密过程，有合法和非法使用
        "SSL": 5,  # 安全套接层，用于安全通信，广泛使用
        "signature": 7,  # 通常与数字签名相关，涉及密钥，较敏感
        "public key": 8,  # 公钥，常在加密和身份验证中使用，较敏感
        "private key": 9,  # 私钥，几乎总是涉及敏感安全操作，非常敏感
        "decrypt": 6,  # 解密操作，有合法和非法使用
    }
}

# 僵尸网络特征模式
botnet_patterns = {
    "Imports": {
        "github/google/gopacket": 5,  # 专门用于网络数据包处理，常见于需要制造或分析网络流量的恶意软件
        "github/google/gopacket/layers": 5,  # 网络层操作库，同上，用于构造或解析不同网络层的数据
        "darkangel/server/client": 9,  # 特定的僵尸网络客户端库，高度特定于恶意软件
        "darkangel/server/constant": 9,  # 特定的常量库，用于僵尸网络，同样高度特定于恶意软件
        "google.golang.org/grpc": 3,  # gRPC库，高效通信，可能用于复杂的恶意软件
        "google.golang.org/grpc/credentials": 2,  # gRPC的凭证管理
        "github.com/Xart3mis/AKILT/Client/lib/DOS/httpflood": 6,  # HTTP洪水攻击库
        "github.com/Xart3mis/AKILT/Client/lib/DOS/slowloris": 6,  # Slowloris攻击库
        "github.com/Xart3mis/AKILT/Client/lib/DOS/udpflood": 6,  # UDP洪水攻击库
        "github.com/Xart3mis/AKILT/Client/lib/keylogger": 7,  # 键盘记录库，明确用于监控用户输入
        "github.com/Xart3mis/AKILT/Client/lib/reg": 6,  # 可能用于注册表操作
        "github.com/Xart3mis/AKILT/Client/lib/webcam": 7,  # Webcam访问库，用于捕获视频
        "github.com/vova616/screenshot": 6,  # 屏幕截图库，用于捕获屏幕图像
        "golang.design/x/hotkey": 6,  # 热键库，用于监听键盘快捷键
        "github.com/kbinani/screenshot": 7,  # 用于捕获多屏幕截图
        "golang.org/x/sys/windows": 7,  # 提供Windows系统调用接口，用于深入系统级操作
        "github.com/shirou/gopsutil": 6,  # 系统信息库，用于获取系统详细状态，可能用于信息收集
        "github.com/miekg/dns": 6,  # DNS库，用于进行复杂的DNS操作和劫持
        "github.com/huin/goupnp": 6  # UPnP库，用于发现和交互网络设备，可能用于网络穿透和服务攻击
    },
    "FunctionCalls": {
        "http.Client.Do": 6,  # 执行HTTP请求，常见于僵尸网络的远程控制和数据传输
        "http.NewRequest": 4,  # 创建HTTP请求，常见于僵尸网络用于构造特定的网络攻击或数据泄露
        "syscall.Socket": 4,  # 直接系统调用创建网络套接字，常用于构建自定义网络通信，尤其是在僵尸网络中
        "net.FilePacketConn": 6,  # 用于创建基于文件描述符的数据包连接，不常见于正常应用程序
        "gopacket.SerializeLayers": 5,  # 用于序列化网络层，常见于动态构造网络攻击数据包
        "syscall.SetsockoptInt": 5,  # 设置套接字选项，常用于配置原始套接字行为，特别是在进行网络攻击时
        "net.Listen": 5,  # 用于设置网络监听，常见于建立控制服务器，特别是在僵尸网络中
        "listener.Accept": 5,  # 接受来自网络的连接请求，关键于构建网络服务，尤其是恶意的命令和控制服务器
        "net.Dial": 2,  # 建立网络连接，常见于建立控制服务器连接，特别是在僵尸网络中
        "conn.Read": 4,  # 从网络连接读取数据，关键于接收来自控制服务器的命令
        "conn.Write": 4,  # 向网络连接写入数据，用于向控制服务器发送响应或数据
        "gob.NewEncoder": 5,  # 创建一个新的GOB编码器，用于数据序列化，常见于恶意软件数据传输
        "enc.Encode": 5,  # 执行数据编码，用于准备发送到控制服务器的数据
        "lis.Accept": 3,  # 接受网络连接，用于服务器或客户端应用
        "grpc.NewServer": 2,  # 创建gRPC服务器，用于构建服务端应用
        "pb.RegisterConsumerServer": 1,  # 在gRPC上注册服务，用于服务端
        "s.Serve": 1,  # 启动gRPC服务，用于服务端操作
        "syscall.LoadLibrary": 4,  # 加载动态链接库，用于访问系统底层API
        "syscall.GetProcAddress": 4,  # 获取函数地址，用于调用系统API
        "keylogger.Run": 7,  # 运行键盘记录，用于监控用户输入
        "exec.Command": 2,  # 执行系统命令，用于执行远程命令或脚本
        "os.OpenFile": 2,  # 打开文件，用于读写文件
        "syscall.Bind": 4,  # 绑定套接字到地址，用于创建恶意服务或监听
        "syscall.Connect": 5,  # 系统级的网络连接函数，用于建立后门连接
        "net.ReverseProxy": 5,  # 实现HTTP反向代理功能，可能用于流量劫持或中间人攻击
        "http.ReverseProxy": 5,  # 实现HTTP反向代理功能，可能用于流量劫持或中间人攻击
        "httputil.ReverseProxy": 5,  # 实现HTTP反向代理功能，可能用于流量劫持或中间人攻击
        "net.SendMail": 2,  # 发送邮件，可能用于数据泄露或通过邮件传播恶意软件
        "log.Print": 4  # 打印日志，可用于僵尸网络
    },
    "Strings": {
        "Infected by exploit": 9,  # 明确指示设备被感染，高度特异性
        "/usr/bin/ssh": 5,  # Linux命令行工具
        "/usr/bin/sh": 5,  # Linux命令行工具
        "/usr/bin/curl": 5,  # 命令行下载工具
        "/usr/bin/tmux": 2,
        "/var/tmp/": 4,  # 常见于Unix系统中用于存储临时文件，恶意软件常用路径
        "wget": 5,  # Linux下下载工具，常用于下载恶意代码或工具
        "curl": 5,  # 另一种命令行下载工具，同上
        "history -c": 6,  # 清除命令历史，常见于试图隐藏行为的恶意软件
        "rm ~/.bash_history": 6,  # 删除用户的bash历史记录，同上
        "chmod 777": 8,  # 修改文件权限为全开放，常见于恶意软件试图增加访问权
        "killall": 7,  # 尝试停止或杀死其他进程，常用于清除系统中的其他恶意软件或安全软件
        "POST": 4,  # HTTP方法，用于发送数据，攻击中常用
        "GET": 3,  # HTTP方法，用于请求数据，普遍用途但在攻击中也常见
        "SOAPAction": 4,  # SOAP协议中的操作指定，常见于针对Web服务的攻击
        "localhost": 1,  # 本地主机地址，普遍用途
        "Connected to server": 4,  # 连接到服务器的日志信息，常见于建立僵尸网络控制连接
        "Write to server failed:": 4,  # 写入服务器失败的日志信息，指示通信问题，常见于僵尸网络错误处理
        "Server send data:": 4,  # 服务器发送数据的日志信息，常见于接收来自控制服务器的命令
        "Couldn't unpack data.": 4,  # 数据解包失败的日志信息，用于错误处理，常见于处理来自控制服务器的复杂命令
        "Couldn't encode output": 4,  # 输出编码失败的日志信息，用于错误处理，常见于数据发送到控制服务器
        "flood": 8,  # 执行网络洪水攻击，特定于DDoS
        "ATTACKING": 9,  # 执行攻击
        "C&C server": 9,  # "Command and Control"服务器地址，特定于僵尸网络
        "shellcode": 8,  # 指向或相关于直接执行的代码片段，常用于恶意活动
        "botnet": 8,  # 明确指向僵尸网络的操作或配置
        "backdoor": 9,  # 后门相关操作或配置
        "keylog": 8,  # 关键词记录功能
        "ddos": 9  # 分布式拒绝服务攻击相关操作或参数

    }
}

# 渗透测试的特征模式
penetration_patterns = {
    "Imports": {
        "crypto/tls": 5,  # 用于处理TLS/SSL连接，可能被用于加密通信，具有一定风险。
        "github.com/elazarl/goproxy": 6,  # 高，因其允许创建代理服务器，可能用于拦截和监视。
        "github.com/robertkrimen/otto": 7,  # 高，这个库用于JavaScript引擎，可能用于执行恶意脚本。
        "github.com/psidex/GoSpy/internal/comms": 9,  # 高，外部库的引用，尤其是与通信相关的，可能涉及数据传输，风险较高。
        "github.com/google/gopacket": 3,  # 用于网络数据包处理，有合法和非法使用场景
        "github.com/google/gopacket/layers": 3,  # 网络层信息提取，有合法和非法使用场景
        "github.com/google/gopacket/pcap": 4,  # 网络抓包处理，合法和非法场景
        "github.com/amoghe/go-crypt": 5,  # 处理密码加密和验证的包，可能用于破解密码。
        "github.com/mattn/go-sqlite3": 3,  # SQLite数据库驱动，用于操作本地数据库，可能被用于提取敏感数据。
        "github.com/miekg/dns": 6,  # DNS查询包，可能用于信息收集或网络探测。
        "github.com/oschwald/geoip2-golang": 6,  # 用于IP地理定位的GeoIP库，可能用于跟踪或侦查。
        "golang.org/x/crypto/ssh": 7,  # SSH库，用于远程连接，可能用于暴力破解SSH密码。
    },
    "FunctionCalls": {
        "http.NewRequest": 6,  # 构造HTTP请求，可能用于发送伪造或恶意请求，具有较高风险。
        "http.Client.Do": 6,  # 发送HTTP请求，可能用于与恶意服务器通信，风险较高。
        "httputil.DumpRequest": 5,  # 调试和拦截HTTP请求，可能被用于中间人攻击，具有较高风险。
        "httputil.DumpResponse": 5,  # 调试和拦截HTTP响应，可能被用于中间人攻击，具有较高风险。
        "goproxy.NewProxyHttpServer": 6,  # 高，因为它设置了一个代理服务器，可能用于拦截流量。
        "goproxy.NewResponse": 4,  # 中等，因为它创建代理响应，可能被操控用于恶意目的。
        "goproxy.OnRequest().DoFunc": 7,  # 高，因为它挂钩了请求处理，可能用于各种攻击。
        "goproxy.OnResponse().DoFunc": 6,  # 中等，因为它处理响应，可能用于数据提取或操控。
        "JSVM.Set": 5,  # 高，设置JavaScript函数，可以在JavaScript中执行代码。
        "JSVM.Run": 5,  # 高，执行JavaScript脚本，可能执行恶意脚本。
        "ioutil.WriteFile": 2,  # 中等，写文件操作，可能用于存储数据或日志。
        "netClient.Do": 5,  # 中等，发送HTTP请求，可能用于外部通信。
        "addCustomEncoder": 7,  # 高，自定义编码器，可能用于处理恶意数据。
        "setHTTPInterceptor": 7,  # 高，设置HTTP拦截器，可能用于拦截和修改请求。
        "exec.Command": 8,  # 高，执行系统命令，可能用于执行恶意代码。
        "cm.RecvBytes": 4,  # 中，接收数据，可能涉及网络数据接收，风险较高。
        "cm.SendBytes": 4,  # 中，发送数据，可能涉及网络数据传输，风险较高。
        "pcap.OpenOffline": 5,  # 打开PCAP文件，通常用于网络分析，但也可能用于恶意行为
        "gopacket.NewPacketSource": 3,  # 创建数据包源，合法和非法使用场景
        "base64.StdEncoding.EncodeToString": 3,  # Base64 编码操作
        "base64.StdEncoding.DecodeString": 3,  # Base64 解码操作
        "testPass": 9,  # 验证明文密码是否匹配加密哈希的函数，典型的暴力破解技术。
        "testTCPConnection": 8,  # 尝试连接指定IP地址和端口，可能被用于端口扫描。
        "sql.Open('sqlite3', locate)": 7,  # 打开SQLite数据库连接，可能被用于读取目标系统中的敏感数据库文件。
        "database.Query": 7,  # 执行SQL查询，从数据库中提取敏感信息如cookie或浏览历史。
        "dns.Exchange": 6,  # 执行DNS查询，可能被用于网络侦察或信息收集。
        "pcap.OpenLive": 6,  # 打开网络接口进行实时数据包捕获，可能用于网络监控。
        "ssh.Dial": 7,  # 尝试通过SSH连接远程主机，可能用于远程访问尝试或暴力破解。
        "ssh.Password": 7,  # 使用密码进行SSH身份验证，可能用于暴力破解。
        "net.DialTimeout": 6,  # 尝试连接指定IP和端口，可能用于扫描开放的SSH端口。
        "session.Run": 6,  # 执行远程命令，可能用于在远程主机上执行恶意操作。

    },
    "Strings": {
        "/'\"><img>\" or 1 = 1/*/../../etc/passwd": 7,  # 典型的SQL注入或XSS攻击payload，具有较高风险。
        "OSPF Pass": 4,  # 认证信息，较敏感但非特定恶意
        "Authentication": 4,  # 认证信息，较敏感但非特定恶意
        "SELECT": 2,  # 查询数据库中的cookie信息，可能用于会话劫持。
        "8.8.8.8:53": 4,  # DNS查询发送目标地址，使用公共DNS服务器可能被修改为恶意目的。
        "/usr/bin/whoami": 5,  # 在远程主机上执行的命令，用于获取当前用户信息。
        "Mozilla/5.0": 2,  # 常见的用户代理，可能用于模仿浏览器行为，风险较低。
        "XSS payload": 5,  # XSS攻击载荷，用于在网页中注入恶意脚本，具有高风险。
        "SQL injection": 5,  # SQL注入攻击，用于非法操作数据库，具有高风险。
        "cmd.exe": 6,  # Windows命令行工具，可能用于执行系统命令，具有高风险。
        "bash -i": 6,  # Unix shell，可能用于远程控制，具有高风险。
        "eval": 5,  # JavaScript中的eval函数，可执行字符串中的代码，具有高风险。
        "base64_decode": 3,  # 常用于解码加密的恶意代码，具有中等风险。
        "passwd": 4,  # 涉及敏感文件，可能用于权限提升，具有中等风险。
        "wget": 5,  # 常用于下载文件，可能用于获取恶意文件，具有中等风险。
        "curl": 5,  # 常用于网络请求，可能用于与恶意服务器交互，具有中等风险。
        "/etc/passwd": 5,  # Unix系统用户信息文件，可能用于获取系统用户信息，具有高风险。
        "ssh-keygen": 5,  # SSH密钥生成工具，可能用于生成未授权的密钥，具有中等风险。
        "nc -l -p": 5,  # Netcat监听模式，可能用于创建反向shell，具有高风险。
        "/bin/sh -i": 6,  # Unix shell交互模式，可能用于执行远程命令，具有高风险。
        "system(": 5,  # PHP中的system函数，可执行外部程序，具有高风险。
        "exec(": 5,  # PHP中的exec函数，执行外部程序，具有高风险。
        "root": 3,  # 根用户，涉及高权限操作，具有中等风险。
        "administrator": 3,  # 管理员账户，涉及高权限操作，具有中等风险。
        "default password": 4,  # 默认密码，涉及安全漏洞，具有中等风险。
        "public exploit": 4,  # 公开的漏洞利用代码，具有中等风险。
        "reverse shell": 6,  # 反向shell，允许远程控制目标机器，具有高风险。
        "malware download": 5,  # 恶意软件下载操作，具有高风险。
        "payload delivery": 5  # 负载传输，涉及恶意软件分发，具有高风险。
    }
}

# 代码混淆的特征模式
obfuscation_patterns = {
    "Imports": {
        "crypto/aes": 4,  # AES加密通常用于安全数据传输，但也可用于隐藏恶意数据。
        "crypto/cipher": 5,  # 提供加密算法接口，可用于执行加密恶意数据的操作。
        "github.com/openshift/must-gather-clean/pkg/obfuscator": 7,  # 用于数据清理和混淆，可能隐藏敏感信息。
        "github.com/openshift/must-gather-clean/pkg/omitter": 6,  # 用于数据省略，可能用于过滤敏感信息。
    },
    "FunctionCalls": {
        "exec.Command": 6,  # 执行外部命令，常用于恶意活动，特别是未验证输入时。
        "command.CombinedOutput()": 6,  # 执行命令并获取输出，可能捕获敏感信息。
        "aes.NewCipher": 4,  # 创建AES加密块，可用于加密数据，风险中等。
        "cipher.NewGCM": 5,  # 创建GCM模式实例，用于加密操作，风险中等。
        "generateDeadCode": 6,  # 生成无效代码，可能用于代码混淆。
        "convertTopLevelFunctionsBodiesLoops": 4,  # 修改函数体中的循环结构，可能用于代码混淆。
        "astutil.Apply": 3,  # 应用AST变换，用于代码结构修改。
        "injectDeadcode": 6,  # 添加无效代码，用于隐藏真实逻辑。
        "encryptStrings": 5,  # 加密字符串，用于隐藏敏感数据。
        "forToTagLoops": 4,  # 转换循环为更复杂的控制流，增加代码阅读难度。
        "randomizeCalls": 4,  # 函数调用随机化，增加分析复杂性。
        "format.Node": 5,  # 格式化代码节点，可能用于代码结构调整。
        "ioutil.WriteFile": 2,  # 写文件操作，可用于输出混淆后的代码。
        "createObfuscatorsFromConfig": 7,  # 根据配置创建混淆器，用于数据和代码混淆。
        "createOmittersFromConfig": 7,  # 根据配置创建省略器，用于数据过滤和隐藏。
        "cleaner.ContentObfuscator.ObfuscateReader": 7,  # 对输入流进行混淆，通常用于保护数据。
        "encipher": 3,  # 执行Vigenère加密，通常用于数据保护。
        "decipher": 3,  # 执行Vigenère解密，用于解密加密数据。
    },
    "Strings": {
        "cmd string": 5,  # 命令字符串，可能用于命令注入。
        "SplitPipe(command)": 4,  # 分割命令序列，可能用于构建复杂的命令链。
        "aesgcm.Seal(...)": 6,  # AES-GCM加密调用，用于数据加密和隐藏。
        "obfuscate_data": 5,  # 用于混淆数据，可能隐藏真实意图。
        "hidden_execute": 5,  # 隐藏的执行命令，可能用于秘密执行恶意活动。
        "keygen_start": 3,  # 密钥生成过程的开始，可能用于加密恶意数据。
        "base64 encoded payload": 7,  # Base64编码的负载，常用于隐藏恶意内容。
        "decrypt_payload": 7,  # 解密负载，可能涉及恶意软件的激活。
        "complex_obfuscation": 5,  # 复杂的代码混淆技术，增加反编译难度。
        "malicious_script": 7,  # 恶意脚本标记，用于识别可能的恶意操作。
        "reverse_shell": 7,  # 反向shell代码，用于远程控制受影响系统。
        "data exfiltration": 7,  # 数据窃取过程，可能涉及敏感信息的非法传输。
        "payload activation": 6,  # 恶意负载激活，标记恶意活动的开始。
        "code injection": 7  # 代码注入过程，用于在运行时修改应用行为。
    }
}

# 钓鱼攻击的特征模式
phishing_patterns = {
    "Imports": {
        "upper.io/db.v3": 4,  # 数据库操作包，用于直接访问和修改数据库，可能被用于数据泄露或篡改。
        "upper.io/db.v3/ql": 4,  # 数据库查询语言部分，可能用于执行复杂的查询或SQL注入。
        "github.com/spf13/viper": 5,  # 配置管理工具，可能用于读取敏感配置，存在被滥用的风险。
        "github.com/PuerkitoBio/goquery": 6,  # HTML解析库，可能用于分析和修改网页内容，常见于钓鱼网站的构建。
        "github.com/gocolly/colly": 7,  # 爬虫框架，可能用于自动化抓取和分析网页数据，用于钓鱼攻击准备。
    },
    "FunctionCalls": {
        "http.ListenAndServe": 6,  # 启动HTTP服务器，可能用于托管钓鱼网站。
        "viper.GetString": 3,  # 从配置中提取字符串，可能用于获取敏感信息。
        "sess.Exec": 7,  # 执行数据库操作，高风险，可能导致SQL注入。
        "goquery.NewDocumentFromReader": 6,  # 解析HTML内容，可能用于钓鱼页面的内容篡改。
        "http.Redirect": 6,  # 执行HTTP重定向，常用于重定向用户到钓鱼网站。
        "colly.Collector.Visit": 7,  # 使用爬虫访问网页，可能用于自动化搜集用户数据。
    },
    "Strings": {
        "javascript:validateForm()": 6,  # JavaScript表单验证代码，可能用于钓鱼网站以欺骗用户输入敏感信息。
        "Please enter your credentials": 5,  # 提示用户输入凭证的文本，常见于钓鱼网页。
        "Your session has expired. Please login again.": 7,  # 会话过期警告，用于诱导用户重新登录，钓鱼网站常用手法。
        "<iframe src=": 8,  # 使用iframe嵌入恶意网站，典型的钓鱼技术。
        "http-equiv='refresh'": 5,  # HTML自动刷新，可能用于自动重定向到钓鱼网站。
        "Unauthorized access is prohibited": 4,  # 假的安全警告，用于增加钓鱼网站的可信度。
        "input[type='password']": 6,  # 寻找密码输入字段，常用于构造钓鱼表单。
        "action='login.php'": 6,  # 表单操作指向登录处理页面，可能是钓鱼网站的一部分。
        "SSL Secure Connection": 5,  # 使用SSL安全连接的声明，可能用于误导用户信任钓鱼网站。
        "Confirm your identity": 7  # 身份确认请求，常见于钓鱼攻击中用于窃取用户凭证。
    }
}

# 载荷的特征模式
payload_patterns = {
    "Imports": {
        "github.com/ssut/payload-dumper-go/chromeos_update_engine": 7,  # 特定的固件更新格式处理，可能涉及恶意固件或数据的操作。
        "crypto/sha256": 4,  # 计算SHA-256哈希，常用于数据完整性检查，也可能用于验证恶意数据。
        "crypto/md5": 3,  # 生成MD5哈希，较低风险但可用于校验文件完整性。
        "github.com/miekg/dns": 5,  # DNS解析库，虽然合法但可以用于网络扫描等目的
        "github.com/google/gopacket/pcap": 6  # pcap用于网络数据包捕获和分析，可能用于网络监控或数据收集
    },
    "Function Calls": {
        "payload.Open": 5,  # 加载和初始化负载，可能涉及恶意操作。
        "payload.ExtractSelected": 5,  # 提取选定的数据，用于详细控制恶意数据的提取。
        "payload.ExtractAll": 6,  # 提取所有数据，可能涉及广泛的恶意数据操作。
        "net.DialTimeout": 6,  # 发起网络连接请求，可能用于网络扫描或连接外部服务器。
        "scanPorts": 8,  # 扫描端口，可能用于探测开放端口，属于潜在恶意行为。
        "net.LookupNS": 7,  # 执行DNS查询，可能用于探测域名信息和子域名，属于潜在风险行为。
        "dns.Exchange": 7,  # 用于进行DNS查询，可能被恶意软件用来进行DNS投毒等攻击
        "pcap.FindAllDevs": 6,  # 查找所有网络设备，这可能用于网络扫描或监控
    },
    "Strings": {
        "payload": 8,  # 恶意负载。
        "CrAU": 3,  # 特定的更新引擎标识符，可能涉及固件或软件更新操作。
        "malware_payload": 6,  # 明确指示恶意负载。
        "decrypt_payload": 5,  # 可能用于解密接收到的恶意数据。
        "payload_signature": 4,  # 与恶意负载签名相关，用于验证负载的完整性或来源。
        "downloaded": 6,  # 表示下载和可能执行的文件，通常是恶意的。
        "unpacking_data": 4,  # 用于描述解包过程，可能涉及恶意数据的处理。
        "' OR 1=1; --": 9,  # SQL注入Payload，明显的恶意代码。
        "' OR '1'='1": 9,  # SQL注入Payload，明显的恶意代码。
        "host := os.Args[1]": 6,  # 通过命令行参数指定主机，可能用于恶意目的。
        "port := os.Args[2]": 6,  # 通过命令行参数指定端口，可能用于恶意目的。
        "kdb": 6,  # 可能与数据库或密钥库有关
        "shadow": 7  # 通常与系统密码文件相关
    }
}

# 防御绕过的特征模式
Defense_Bypass_patterns = {
    "Imports": {
        "github.com/panjf2000/ants/v2": 7,  # 高性能协程池，可能被用于大规模并发攻击。
        "github.com/zan8in/oobadapter/pkg/oobadapter": 8,  # OOB适配器，可能用于远程通信或漏洞利用。
        "retryhttpclient": 6,  # 网络请求重试机制，可能被恶意使用来隐藏网络流量。
        "cyberspace": 5,  # 网络扫描和信息收集，可能引发安全隐患。
        "oobadapter": 8,  # OOB通信，可能用于木马程序的隐蔽通信。
        "syscall": 4,  # 系统调用接口，可能涉及低级别的系统操作或权限提升。
        "crypto/tls": 6,  # 用于加密传输层安全协议，可能涉及数据拦截或篡改。
        "golang.org/x/net/proxy": 5,  # 代理支持库，用于绕过网络监控。
        "github.com/corpix/uarand": 4,  # 用户代理字符串库，用于伪装网络请求。
        "github.com/spf13/viper": 4,  # 配置管理库，可能用于配置绕过策略。
        "github.com/hashicorp/go-rootcerts": 2,  # 根证书加载，可能被用来信任自签名证书。
    },
    "FunctionCalls": {
        "AbuseIPDB": 4,  # 检测IP是否存在恶意行为，可能用于识别或规避攻击目标。
        "SetOOBAdapter": 5,  # 设置OOB适配器，可能与远程通信或漏洞检测有关。
        "executeExpression": 4,  # 运行表达式或命令，可能与攻击行为相关。
        "ants.NewPoolWithFunc": 5,  # 并发池管理函数指针，可能被用于并发执行大规模攻击任务。
        "oobadapter.NewOOBAdapter": 5,  # 配置OOB适配器，可能涉及外部通信或命令接收。
        "options.CreatePocList": 5,  # 生成PoC列表，可能是漏洞利用的准备工作。
        "options.Targets.List": 6,  # 获取目标列表，可能用于多目标攻击或扫描。
        "recover": 5,  # 捕获panic，可能用于确保恶意软件异常后仍继续执行。
        "runner.OnResult": 6,  # 处理任务结果，可能涉及漏洞或攻击结果的报告。
        "runner.NotVulCallback": 5,  # 未识别到漏洞时的回调，可能用于攻击后的响应处理。
        "retryhttpclient.Init": 7,  # 初始化网络客户端，可能隐藏恶意流量或进行网络攻击。
        "cyberspace.New": 4,  # 创建网络空间对象，可能用于扫描或信息收集。
        "report.NewJsonReport": 6,  # 生成JSON报告，可能用于导出敏感信息。
        "report.NewReport": 6,  # 生成报告，可能用于攻击者的数据记录。
        "oobadapter.OOBAdapter": 8,  # 初始化OOB适配器，可能用于木马程序的后门通信。
        "runner.monitorTargets": 7,  # 监控目标系统，可能用于触发特定条件下的攻击。
        "runner.Cyberspace.GetTargets": 7,  # 获取扫描或攻击目标，可能用于发现可攻击系统。
        "tls.DialWithDialer": 4,  # 用于建立安全的TLS连接，可能被滥用来进行恶意通信。
    },
    "Strings": {
        "path": 6,  # 环境变量操作，可能涉及文件系统访问与修改，风险较高。
        "OOB": 8,  # Out-of-Band 相关，可能涉及远程控制或漏洞利用。
        "ReversePocs": 7,  # 反向扫描PoC，常用于渗透测试中的攻击技术。
        "SkipVerify": 6,  # 跳过证书验证，可能导致安全漏洞或中间人攻击。
    }
}


# 键盘记录器
Keyboard_patterns = {
    "Imports": {
        "unsafe": 5,  # 进行不安全的内存操作,需要精确的内存管理才能产生恶意影响
        "github.com/atotto/clipboard": 6,  # 可以访问剪贴板数据
        "golang.org/x/sys/windows/registry": 5,  # 可能被用来隐藏或删除恶意软件的启动路径
        "github.com/go-vgo/robotgo": 4,  # 第三方库，用于获取窗口标题和控制鼠标/键盘
        "github.com/robotn/gohook": 6,  # 第三方库，用于捕捉全局键盘和鼠标事件
        "net/smtp": 4,  # 用于通过SMTP协议发送邮件
        "github.com/kindlyfire/go-keylogger": 9,  # 提供键盘记录功能
        "github.com/kbinani/screenshot": 5,  # 提供屏幕截图功能
    },
    "FunctionCalls": {
        "CreateKeylogFile": 3,  # 创建一个用于存储键盘记录的文件,如果用于存储键盘记录，可能存在恶意风险
        "SetWindowsHookEx": 6,  # 设置钩子以监控键盘事件，通常用于键盘记录,在恶意软件中，这是关键功能
        "getWindowText": 3,  # 可以用于记录用户当前正在使用的窗口标题，风险在于可能泄露用户隐私
        "WindowLogger": 4,  # 持续记录用户当前活动窗口的标题，并将其写入日志, 这种行为可能用于监视用户活动
        "Keylogger": 8,  #: 这是主要的键盘记录功能，用于捕获用户的键盘输入，风险极高
        "clipboardLogger": 5,  # 监控并记录用户剪贴板内容，可能会捕获敏感信息，如密码或个人信息
        "listenClipboard": 2,  # 监控剪贴板内容的变化，并记录日志
        "listenKeyboard": 4,  # 捕获键盘事件并记录日志
        "afterExecuteBehavior": 5,  # 执行PowerShell命令显示错误消息
        "getForegroundWindow": 4,  # 调用Windows API获取当前活动窗口的句柄
    },
    "Strings": {
        "dump": 4,  # 暗示与某些软件有关联，这是为了伪装成合法文件
        "Clipboard": 5,  # 记录剪贴板内容可能导致用户复制的敏感信息（如密码、银行账号等）被泄露
        "upload succeeded": 3,  # 表明数据可能已经被非法上传到远程服务器
        "keylogger.log": 7,  # 表明了日志的内容是键盘记录
        "keylogger.db": 7,  # 表示数据内容是键盘记录
        "sync.exe": 5,  # 恶意进程名称
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Run": 5,  # 用于存放系统启动项
        "tasklist": 2,  # 获取系统中所有正在运行的进程列表
        "taskkill": 7,  # 清除恶意进程，但也可能被滥用于杀掉系统中的关键进程
    }
}


# 后门软件
trojan_patterns = {
    "Imports": {
        "syscall": 4,  # 可用于低级别系统操作，包括隐藏窗口等
        "golang.org/x/net/icmp": 4,  # 处理 ICMP 协议的库，用于发送和接收 ICMP 消息
        "github.com/pilebones/backdoorGolang/core/cli": 8,  # 表明这个库的目的是创建后门
        "github.com/pilebones/backdoorGolang/core/socket/server": 7,  # 通常用于监听和接受远程连接，这可能被用于实现恶意后门
        "github.com/google/gopacket/layers": 7,  # 意软件中常用的库，用于监控和操控网络流量
        "github.com/google/gopacket/pcap": 7,  # 用于网络嗅探和监听
        "github.com/google/gopacket": 6,  # 处理和分析网络数据包的库，常用于网络监控和数据包分析
        "GOback/actions": 6,  # 第三方包，用于获取进程列表和注入代码
        "GOback/helpers": 6,  # 第三方包，用于复制文件和修改注册表
        "golang.org/x/crypto/ssh": 2,  # 实现 SSH 协议
        "github.com/kbinani/screenshot": 5,  # 提供屏幕截图功能
        "github.com/jm33-m0/emp3r0r/core/lib/tun": 6,  # 网络隧道功能在恶意软件中常见
        "github.com/jm33-m0/emp3r0r/core/lib/util": 3,  # 工具函数可以用于各种操作，包括恶意操作
        "github.com/jm33-m0/go-cdn2proxy": 4,  # 可能用于隐藏真实的 IP 地址
        "github.com/ncruces/go-dns": 3,  # 可能用于加密 DNS 查询，以防止流量分析
        "src.elv.sh/pkg/shell": 3,  # 可能用于实现自定义 shell，具有潜在的恶意用途
        "github.com/gobuffalo/packr": 3,  # 打包和服务静态文件
        "github.com/emersion/go-imap/client": 5,  # 用于连接邮件服务器，可能涉及到获取邮件内容
        "github.com/emersion/go-imap": 5,  # 用于处理邮件协议，可能涉及到邮件数据获取
        "github.com/vova616/screenshot": 7,  # 捕获屏幕截图
        "github.com/d0zer/elfinfect": 6,  # 与ELF文件的“感染”相关功能
    },
    "FunctionCalls": {
        "askForAllPerms": 4,  # 询问用户是否允许程序收集所有类型的数据
        "askForSystemInfo": 4,  # 询问用户是否允许收集系统信息
        "GetSystemInfo": 6,  # 收集系统信息
        "GetHostname": 3,  # 获取主机名,于识别和标识受感染的系统
        "p.URLTest": 5,  # 可能被用于测试恶意站点或收集信息
        "outbound.ParseProxy": 6,  # 解析代理配置的函数，处理自定义配置的内容
        "NewTrojan": 6,  # 涉及网络配置和 Trojan 协议
        "CopyFile": 3,  # 复制文件函数，常用于文件操作
        "EncryptDecrypt": 2,  # 如果用于保护恶意数据，可能存在风险
        "encrypt": 2,  # 加密
        "decrypt": 2,  # 解密
        "client": 4,  # 具有明显的隐秘通信和数据窃取风险
        "ListenPacket": 3,  # 用于监听网络数据包。可能涉及到网络通信的敏感数据处理
        "dualStackDialContext": 3,  # 涉及到并发和不同协议的处理
        "VirtualProtect": 7,  # 使用 VirtualProtect 修改内存保护属性是常见的恶意技术
        "Implant": 8,  # 修改内存权限，以便执行注入的shellcode
        "cmd.SysProcAttr": 7,  # 可以被用于远程命令执行
        "beginListen": 7,  # 恶意功能，用于隐蔽的数据传输和接收控制指令
        "executeServerCommand": 6,  # 可被用来执行恶意操作和控制服务器行为
        "monitorFile": 6,  # 监视指定文件的存在，并将文件内容发送到指定地址
        "executeCommand": 7,  # 执行传入的系统命令，并将结果返回,具有明显的恶意潜力
        "craftPacket": 6,  # 构造网络数据包，并将数据插入源端口
        "sendAuthPacket": 4,  # 用于发送加密的认证数据包
        "fileWait": 5,  # 用于隐蔽的数据传输和恶意文件下载
        "helpers.CopyFile": 5,  # 用于持久化恶意代码，确保恶意软件在系统重启后仍然存在
        "helpers.AddRegistery": 6,  # 用于使恶意软件在系统启动时自动运行
        "actions.GetAllProcesses": 7,  # 获取系统中所有进程的PID,通常用于恶意进程注入或监控
        "actions.InjectShellCode": 9,  # 将Shellcode注入到一个进程中
        "getPayloadFromEnv": 7,  # 用于将恶意负载注入到目标中
        "Shoff": 7,  # 调整节区表的偏移量以便插入负载
        "t.Payload.Write": 9,  # 将负载数据和调整代码写入 ELF 文件
        "modEpilogue": 9,  # 插入相应的修复代码
        "TextSegmentPaddingInfection": 9,  # 将负载数据插入到文本段，并更新文件内容
        "agent.SetProcessName": 4,  # 设置进程名称。可能用于伪装进程
        "agent.HidePIDs": 7,  # 隐藏进程 ID
        "agent.CheckIn": 6,  # 向控制服务器报告状态,典型的C2(命令与控制)行为
        "agent.ConnectCC": 6,  # 连接到控制服务器,典型的C2行为
        "agent.CCMsgTun": 6,  # 处理C2消息隧道,用于隐藏通信
        "cdn2proxy.StartProxy": 5,  # 启动 CDN 代理,用于隐藏流量来源
        "agent.ApplyRuntimeConfig": 4,  # 应用运行时配置,可能涉及恶意配置
        "agent.ExtractBash": 4,  # 提取Bash,可能用于在目标系统上执行脚本
        "agent.IsAgentRunningPID": 4,  # 检查代理是否在运行,用于管理代理实例
        "HostFiles": 3,  # 可以用于提供恶意文件下载
        "CheckExtension": 5,  # 检查常见文档类型，并上传这些文件
        "createbox": 6,  # 通过 GUI 收集用户的电子邮件凭证
        "sshupload": 6,  # 将数据上传到远程服务器的指定目录
        "uploadscreenshot": 7,  # 涉及上传屏幕截图到远程服务器
        "takescreenshot": 7,  # 捕获当前屏幕截图并将其上传
        "lookupHash": 5,  # 获取 VirusTotal 文件报告
        "webAvScan": 6,  # 允许上传和扫描文件，涉及用户文件数据处理
        "webAvLookup": 5,  # 允许根据 hash 查询数据，涉及外部数据访问
    },
    "Strings": {
        "skip-cert-verify": 3,  # 代理配置字段，涉及敏感配置
        "Trojan": 4,  # 与木马相关
        "received": 4,  # 用于 ICMP 消息的数据
        "/tmp/.bash_history": 5,  # 用于读取用户的 Bash 历史记录，可能包含敏感信息
        "0.0.0.0": 5,  # 表示监听所有网络接口
        "shellcode": 9,  # 恶意代码的一部分，通常用于攻击
        "msfvenom": 6,  # 这个工具常用于生成恶意负载
        "Windows TCP Backdoor": 7,  # 表明程序的设计目的是创建一个 TCP 后门
        "Listening on %s:%d": 6,  # 程序将在特定的 IP 地址和端口上监听连接
        "Monitoring file": 7,  # 通知监视文件的状态
        "Would you grant me a permission to [system information; files lookup; ]": 5,  # 用于请求数据访问权限
        "wmic partition get name,size,type": 6,  # 用于获取磁盘分区信息
        "https://discord.com/api": 6,  # 用来将数据发送到攻击者控制的Discord频道
        "chromeupdate.exe": 7,  # 恶意文件名，伪装成Chrome更新程序
        "lscpu": 5,  # 收集系统硬件信息
        "lsblk": 5,  # 收集设备信息
        "lspci": 5,  # 收集详细的硬件信息
        "TextSegmentPadding": 6,  # 感染算法的名称
        "PtNoteToPtLoad": 6,  # 感染算法的名称
        "/proc/self/exe": 5,  # 用于获取当前进程的路径,常用于隐藏或伪装进程
        "socks5://127.0.0.1": 5,  # 用于Tor代理的配置,代理通常用于隐藏真实来源
        "https://9.9.9.9/dns-query": 4,  # DoH服务器配置,加密 DNS 查询以防止流量分析
    }
}

# 勒索软件
ransomware_patterns = {
    "Imports": {
        "crypto/rsa": 7,  # 用于加密文件，典型的勒索软件操作
        "crypto/rand": 4,  # 生成加密用的随机数，常见于加密过程
        "crypto/sha256": 5,  # 常用于生成文件校验值，确保文件未被篡改
        "math/big": 3,  # 处理大数运算，通常用于密码学相关操作
        "github.com/btcsuite/btcd/btcec": 6,  # 处理比特币交易，可能用于处理赎金支付
        "github.com/btcsuite/btcutil": 6,  # 同上，用于比特币地址和交易管理
        "github.com/skratchdot/open-golang/open": 6,  # 打开文件或URL，可能用于显示勒索说明
        "github.com/gustavohenrique/ransomware/cryptography": 9,  # 明确的勒索软件加密库
        "github.com/gustavohenrique/ransomware/util": 9,  # 同上，用于勒索软件的实用工具
        "github.com/ecies/go": 6,  # 高级加密标准，可能用于加密文件
        "github.com/NextronSystems/ransomware-simulator/lib/note": 8,  # 用于生成和显示勒索说明的库
        "github.com/NextronSystems/ransomware-simulator/lib/shadowcopy": 8,  # 删除系统恢复点，防止文件恢复
        "github.com/NextronSystems/ransomware-simulator/lib/simulatemacro": 8,  # 模拟宏攻击，用于传播勒索软件
        "github.com/huin/goupnp": 4,  # UPnP库，可能用于网络穿透，助攻勒索软件的远程控制
        "github.com/go-sql-driver/mysql": 4,  # 数据库驱动，可能用于存储被加密文件的信息
        "github.com/spf13/afero": 5,  # 文件系统抽象库，用于操作文件系统中的文件
        "github.com/elastic/beats/v7/libbeat/common": 5  # 用于收集系统数据，可能用于监控被勒索系统的状态
    },
    "FunctionCalls": {
        "handler": 5,  # 通常用于处理加密或解密操作
        "CreatePrivateKey": 5,  # 生成私钥，可能用于创建唯一的解密密钥
        "encryptDir": 9,  # 加密指定目录，典型的勒索操作
        "decryptDir": 9,  # 解密操作，通常配合赎金支付后使用
        "util.GenerateRansomwareHtmlPage": 9,  # 生成勒索通知页面，高风险行为
        "encryptOrDecrypt": 8,  # 文件加密或解密，核心勒索软件功能
        "generateECIESKeyPair": 6,  # 生成加密密钥对，用于文件加密
        "compileEncryptor": 6,  # 编译加密模块，确保勒索软件能有效执行
        "compileDecryptor": 6,  # 编译解密模块，仅供赎金支付后使用
        "setWallpaper": 7,  # 更改桌面壁纸为勒索通知，提高用户警觉
        "getDrives": 8,  # 获取系统驱动器列表，用于全盘加密
        "deco": 7,  # 解密操作，一般在支付赎金后提供
        "enco": 7,  # 加密操作，加密目标文件
        "copyExecutable": 7,  # 复制可执行文件到其他位置，用于持久化和自启动
        "shutdownSystems": 7  # 关闭系统服务，增加恢复难度
    },
    "Strings": {
        "Private Key": 7,  # 用于加密文件的私钥
        "Public Address": 7,  # 比特币公共地址，用于接收赎金
        "EncryptDir": 9,  # 直接相关于加密文件目录
        "cDecryptDir": 9,  # 直接相关于解密文件目录
        "RANSOMWARE_URL": 7,  # 勒索软件C&C服务器的URL
        "RANSOMWARE_PORT": 7,  # 勒索软件通信端口
        "privateKeyFilename": 5,  # 私钥文件名，存储加密密钥
        "publicKeyFilename": 5,  # 公钥文件名，分发给受害者以验证支付
        "paid": 8,  # 用于确认赎金支付的状态
        "startupBanner": 6,  # 启动时显示的勒索通知
        "-X 'Prince-Ransomware/configuration.PublicKey=%s'": 9,  # 用于配置攻击者的公钥
        "-X 'Prince-Decryptor/configuration.PrivateKey=%s'": 9,  # 用于配置攻击者的私钥
        "PowerShell": 6,  # 使用PowerShell执行系统级操作
        ".ruscary": 8,  # 文件后缀，标记加密过的文件
        "key.key": 7,  # 加密密钥文件名
        "shadow copy deletion": 8,  # 指示删除影子副本
        "document encryption": 8,  # 指示加密文档
        "ransomware": 8,  # 勒索通知
        "Run Ransomware": 4,  # 运行勒索软件模拟器
        "vssadmin delete shadows": 9,  # 删除系统恢复点，常见于勒索软件操作
        "Copying executable": 8,  # 伪装执行文件，提高潜在的欺骗性
        "Staging execution": 8,  # 使用伪装的Office程序执行恶意操作
        "Dropping ransomware": 8  # 生成勒索通知，提醒用户支付赎金
    }
}

# 内核攻击 特征模式
kernel_patterns = {
    "Imports": {
        "cve_2021_3449/tls": 8,  # 自定义 TLS 实现，可能针对 CVE-2021-3449 漏洞
        "github.com/google/nftables": 3,  # 与系统防火墙相关
        "github.com/vishvananda/netns": 3,  # 涉及网络命名空间的创建和操作
        "github.com/gorilla/websocket": 4,  # 这个库在恶意和合法代码中都可能使用
        "github.com/chromedp/chromedp": 6,  # 可以用来自动化访问恶意payload
        "golang.org/x/sys/unix": 5,  # 提供底层系统调用接口
        "github.com/iovisor/gobpf/elf": 7,  # 用于加载BPF程序到内核，可能用于性能监控或恶意行为
        "github.com/hpcloud/tail": 4,  # 用于文件尾部跟踪，可能用于日志文件监控
        "syscall": 4,  # 直接进行系统调用，常见于需要直接与操作系统内核交互的代码
        "golang.org/x/crypto/nacl/secretbox": 5,  # 用于加密，可能隐藏恶意行为
        "github.com/shirou/gopsutil": 4,  # 系统监控工具库，可用于收集系统信息
        "github.com/mitchellh/go-ps": 5,  # 进程列表获取，可用于监控或隐藏特定进程
        "github.com/juju/ratelimit": 2,  # 用于流量控制，可能用于控制恶意通信的带宽使用
        "github.com/google/gopacket": 7  # 用于网络数据包处理，可能用于数据包捕获或伪造
    },
    "FunctionCalls": {
        "packet_ropchain_path": 6,  # ROP链的发送很可能用于攻击
        "craft_rop_chain": 9,  # 构造ROP链以利用内核漏洞
        "leak_module_step": 7,  # 设置nftables规则以泄露内存信息
        "conn.AddRule": 9,  # 向nftables链中添加规则，以操控内核内存或泄露信息
        "conn.GetSetElements": 7,  # 从内核中检索泄漏集的元素
        "traceconn.JoinGroup": 5,  # 跟踪信息可以获取有关内核内部的详细数据
        "ropchain_step": 9,  # ROP 链是利用系统漏洞的常见手法
        "packet_leak_path": 7,  # 名称暗示可能用于泄漏数据
        "sendInvalidWebSocketMessage": 6,  # 构造一个格式不正确的WebSocket消息
        "queryEnum": 7,  # 尝试发现并利用网站的Prototype Pollution漏洞
        "filepath.Clean": 8,  # 测试或利用路径遍历漏洞
        "filepath.Join": 7,  # 构建的路径可能会绕过预期的目录结构，从而访问敏感文件
        "syslog": 2,  # 日志记录功能，可能用于记录攻击详情
        "modprobe": 8,  # 加载和卸载内核模块，可能用于加载恶意模块
        "exec.Command": 9,  # 执行外部命令，可用于执行恶意脚本或程序
        "dmesg": 3,  # 查看内核消息，可能用于调试或信息搜集
        "bpf": 8,  # 使用Berkeley Packet Filter，可能用于复杂的数据包处理或监控
        "mmap": 9,  # 内存映射，常用于内存操作相关的漏洞利用
        "munmap": 7,  # 取消内存映射，用于管理内存，可能涉及资源清理
        "ioctl": 9,  # 设备驱动通信，常见于硬件相关的攻击或配置修改
    },
    "Strings": {
        "shellcode": 6,  # 典型的内核利用shellcode
        "leak-set": 5,  # 上下文中的使用可能与信息泄露攻击相关
        "leak-chain": 5,  # 上下文中的使用可能与信息泄露攻击相关
        "module_leak": 7,  # 涉及模块泄漏
        "kernel_leak": 7,  # 涉及内核泄漏
        "kernel_rop": 7,  # 涉及 ROP（返回导向编程）链
        "WeaverExloit-All.exe": 8,  # 表明这是一个利用工具或攻击程序
        "-p QVD-2023-5012": 9,  # 指代具体的漏洞
        "-p CVE-2023-2523": 9,  # 指代具体的漏洞
        "-p CVE-2023-2648": 9,  # 指代具体的漏洞
        "CVE-2023-35001": 9,  # 指代具体的漏洞
        "CVE-2021-3449": 9,  # 指代具体的漏洞
        "-f c:\\windows\\win.ini": 6,  # 用于获取敏感信息或进一步的攻击
        "CVE-2020-13935": 9,  # 指代具体的漏洞
        "payloads": 8,  # 具有明显的攻击性，尝试利用和发现安全漏洞
        "CVE-2021-43798": 9,  # 指代具体的漏洞
        "usermode": 4,  # 用户模式执行环境，相关于权限提升攻击
        "kernelmode": 8,  # 内核模式执行环境，高风险攻击行为
        "rootkit": 9,  # 根植木马或隐藏工具，高风险
        "zero-day": 9,  # 零日漏洞，常指尚未公开的高风险漏洞
        "privileged escalation": 9,  # 权限提升，直接涉及安全绕过
        "memory corruption": 8,  # 内存损坏，常见于复杂攻击中
        "buffer overflow": 9,  # 缓冲区溢出，经典的攻击技术
        "race condition": 7,  # 竞态条件，可能用于绕过同步机制
        "system call": 5,  # 系统调用，常用于直接与操作系统内核交互
        "syscall hooking": 9,  # 系统调用劫持，用于监控或修改系统行为
        "undocumented API": 7,  # 未公开的API调用，可能涉及隐秘的系统功能利用
    }
}
