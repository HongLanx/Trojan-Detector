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

#渗透测试的特征模式
suspicious_patterns = {
    "Imports": {
        "bufio": 3,  # 读取/写入操作，可用于处理输入/输出数据，存在一定风险。
        "compress/gzip": 3,  # 数据压缩和解压缩功能，通常风险较低，但可能用于隐藏数据。
        "crypto/tls": 5,  # 用于处理TLS/SSL连接，可能被用于加密通信，具有一定风险。
        "golang.org/x/net/html": 4,  # HTML解析库，风险较低，但可能用于解析或注入恶意内容。
        "github.com/elazarl/goproxy": 7,  # 高，因其允许创建代理服务器，可能用于拦截和监视。
        "github.com/robertkrimen/otto": 7,  # 高，这个库用于JavaScript引擎，可能用于执行恶意脚本。
        "github.com/psidex/GoSpy/internal/comms": 9,  # 高，外部库的引用，尤其是与通信相关的，可能涉及数据传输，风险较高。
        "github.com/google/gopacket": 4,  # 用于网络数据包处理，有合法和非法使用场景
        "github.com/google/gopacket/layers": 4,  # 网络层信息提取，有合法和非法使用场景
        "github.com/google/gopacket/pcap": 4,  # 网络抓包处理，合法和非法场景
        "encoding/base64": 5,  # Base64 编码库，广泛用于数据编码
        "github.com/amoghe/go-crypt": 8,  # 处理密码加密和验证的包，可能用于破解密码。
        "github.com/mattn/go-sqlite3": 7,  # SQLite数据库驱动，用于操作本地数据库，可能被用于提取敏感数据。
        "github.com/miekg/dns": 6,  # DNS查询包，可能用于信息收集或网络探测。
        "github.com/oschwald/geoip2-golang": 6,  # 用于IP地理定位的GeoIP库，可能用于跟踪或侦查。
        "golang.org/x/crypto/ssh": 8,  # SSH库，用于远程连接，可能用于暴力破解SSH密码。
    },
    "FunctionCalls": {
        "http.NewRequest": 6,  # 构造HTTP请求，可能用于发送伪造或恶意请求，具有较高风险。
        "http.Client.Do": 6,  # 发送HTTP请求，可能用于与恶意服务器通信，风险较高。
        "ioutil.ReadAll": 4,  # 读取所有数据，可能被用于处理敏感信息。
        "gzip.NewReader": 4,  # 解压缩数据，通常风险较低，但可能用于解码隐藏数据。
        "html.NewTokenizer": 4,  # HTML解析，风险较低，但可能用于注入或解析恶意内容。
        "httputil.DumpRequest": 5,  # 调试和拦截HTTP请求，可能被用于中间人攻击，具有较高风险。
        "httputil.DumpResponse": 5,  # 调试和拦截HTTP响应，可能被用于中间人攻击，具有较高风险。
        "goproxy.NewProxyHttpServer": 8,  # 高，因为它设置了一个代理服务器，可能用于拦截流量。
        "goproxy.NewResponse": 6,  # 中等，因为它创建代理响应，可能被操控用于恶意目的。
        "goproxy.OnRequest().DoFunc": 7,  # 高，因为它挂钩了请求处理，可能用于各种攻击。
        "goproxy.OnResponse().DoFunc": 6,  # 中等，因为它处理响应，可能用于数据提取或操控。
        "JSVM.Set": 7,  # 高，设置JavaScript函数，可以在JavaScript中执行代码。
        "JSVM.Run": 7,  # 高，执行JavaScript脚本，可能执行恶意脚本。
        "ioutil.WriteFile": 4,  # 中等，写文件操作，可能用于存储数据或日志。
        "netClient.Do": 5,  # 中等，发送HTTP请求，可能用于外部通信。
        "addCustomEncoder": 7,  # 高，自定义编码器，可能用于处理恶意数据。
        "setHTTPInterceptor": 7,  # 高，设置HTTP拦截器，可能用于拦截和修改请求。
        "exec.Command": 9,  # 高，执行系统命令，可能用于执行恶意代码。
        "cm.RecvBytes": 7,  # 中，接收数据，可能涉及网络数据接收，风险较高。
        "cm.SendBytes": 7,  # 中，发送数据，可能涉及网络数据传输，风险较高。
        "pcap.OpenOffline": 5,  # 打开PCAP文件，通常用于网络分析，但也可能用于恶意行为
        "gopacket.NewPacketSource": 4,  # 创建数据包源，合法和非法使用场景
        "base64.StdEncoding.EncodeToString": 3,  # Base64 编码操作，合法用途
        "base64.StdEncoding.DecodeString": 3,  # Base64 解码操作，合法用途
        "testPass": 9,  # 验证明文密码是否匹配加密哈希的函数，典型的暴力破解技术。
        "testTCPConnection": 8,  # 尝试连接指定IP地址和端口，可能被用于端口扫描。
        "sql.Open('sqlite3', locate)": 7,  # 打开SQLite数据库连接，可能被用于读取目标系统中的敏感数据库文件。
        "database.Query": 7,  # 执行SQL查询，从数据库中提取敏感信息如cookie或浏览历史。
        "dns.Exchange": 6,  # 执行DNS查询，可能被用于网络侦察或信息收集。
        "pcap.OpenLive": 6,  # 打开网络接口进行实时数据包捕获，可能用于网络监控。
        "ssh.Dial": 8,  # 尝试通过SSH连接远程主机，可能用于远程访问尝试或暴力破解。
        "ssh.Password": 7,  # 使用密码进行SSH身份验证，可能用于暴力破解。
        "net.DialTimeout": 6,  # 尝试连接指定IP和端口，可能用于扫描开放的SSH端口。
        "session.Run": 6,  # 执行远程命令，可能用于在远程主机上执行恶意操作。
    },
    "Strings": {
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36": 4,  # 伪造User-Agent字符串，可能用于欺骗或伪装为合法浏览器，有一定风险。
        "https://": 5,  # HTTPS URL，可能用于与恶意服务器建立加密通信，具有较高风险。
        "/'\"><img>\" or 1 = 1/*/../../etc/passwd": 7,  # 典型的SQL注入或XSS攻击payload，具有较高风险。
        "OSPF Pass": 4,  # 认证信息，较敏感但非特定恶意
        "Authentication": 4,  # 认证信息，较敏感但非特定恶意
        "SELECT host, name, value FROM moz_cookies": 7,  # 查询数据库中的cookie信息，可能用于会话劫持。
        "SELECT url, datetime(visit_date/1000000, 'unixepoch') FROM moz_places, moz_historyvisits WHERE visit_count > 0 AND moz_places.id == moz_historyvisits.place_id;": 7,  # 查询浏览历史记录，可能暴露用户隐私数据。
        "passfile, dictionary": 8,  # 文件路径参数，用于指定密码文件和字典，常用于密码破解程序。
        "8.8.8.8:53": 6,  # DNS查询发送目标地址，使用公共DNS服务器可能被修改为恶意目的。
        "/usr/bin/whoami": 6,  # 在远程主机上执行的命令，用于获取当前用户信息。
        "ip+':'+strconv.Itoa(port)": 7,  # 拼接IP地址和端口号字符串，用于网络扫描或探测。
    }
}

#代码混淆的特征模式
suspicious_patterns = {
    "Imports": {
        "crypto/aes": 8,  # 用于AES加密，虽然加密是安全的，但在恶意代码中可能被用来隐藏敏感信息或恶意数据。
        "crypto/cipher": 8,  # 提供加密算法接口，容易被用于执行加密恶意数据的操作。
        "github.com/openshift/must-gather-clean/pkg/obfuscator": 6,
        "github.com/openshift/must-gather-clean/pkg/omitter": 6,
    },
    "FunctionCalls": {
        "exec.Command": 9,  # 执行外部命令的核心函数，存在命令注入的风险，特别是当输入未经验证时。
        "command.CombinedOutput()": 7,  # 执行命令并获取输出，容易被利用来捕获敏感信息或处理复杂的命令链。
        "aes.NewCipher": 8,  # 创建一个AES加密块，可能用于加密恶意数据或隐藏代码。
        "cipher.NewGCM": 7,  # 创建一个GCM模式实例，用于执行认证加密操作，可能用于加密和保护恶意数据。
        "generateDeadCode": 7,  # 生成死代码的函数，可能用于代码混淆或注入。
        "injectDeadcode": 6,  # 注入死代码的函数，直接修改目标代码，潜在风险较高。
        "astutil.Apply": 6,  # 用于应用 AST 转换的函数，可能用于修改代码结构。
        "forToTagLoops": 6,  # 转换函数体中的 for 循环为标记和 goto 语句，可能用于代码混淆。
        "convertTopLevelFunctionsBodiesLoops": 6, # 修改顶级函数体中的循环结构，潜在的恶意代码注入。
        "astutil.Apply": 6,  # 用于应用 AST 转换的函数，可能用于修改代码结构。
        "injectDeadcode": 7,     # 添加无用代码，可能用于代码混淆或隐藏恶意代码。
        "encryptStrings": 6,     # 加密字符串，通常用于混淆和隐藏真实数据。
        "forToTagLoops": 6,      # 将循环转换为标记和 goto 语句，可能用于代码混淆。
        "randomizeCalls": 6,     # 随机化函数调用，可能用于混淆函数调用路径。
        "format.Node": 5,        # 用于格式化 Go 代码，通常用于代码修改后的输出。
        "ioutil.WriteFile": 4,   # 写入文件，可能用于修改源代码。
        "createObfuscatorsFromConfig": 6,  # 从配置中创建混淆器，可能用于混淆数据。
        "createOmittersFromConfig": 6,  # 从配置中创建省略器，可能用于数据过滤。
        "cleaner.ContentObfuscator.ObfuscateReader": 7,  # 对输入流进行混淆，通常用于保护数据。
        "encipher": 3,  # Vigenère加密，属于加密操作
        "decipher": 3,  # Vigenère解密，属于加密操作
    },
    "Strings": {
        "cmd string": 8,  # 用户输入的命令字符串，如果未经过滤或验证，可能导致命令注入攻击。
        "SplitPipe(command)": 5,  # 将命令通过管道分割的函数，尽管功能正常，但可能会被用来构建复杂的命令序列。
        "aesgcm.Seal(nil, nonce, []byte(real.Value[1:len(real.Value)-1]), nil)": 8,  # 加密数据并封装输出，可能用于隐藏敏感数据或恶意内容。
        "Chiffre de Vigenère": 3,  # Vigenère加密算法名，属于加密相关
    }
}

#钓鱼攻击的特征模式
suspicious_patterns = {
    "Imports": {
        "upper.io/db.v3": 7,  # 数据库操作包，直接访问和修改数据库，可能被用于数据泄露或篡改。
        "upper.io/db.v3/ql": 7,  # 与数据库操作相关，潜在的SQL注入风险。
        "github.com/spf13/viper": 6,  # 应用配置管理，错误或恶意配置可能导致安全漏洞。
        "github.com/PuerkitoBio/goquery": 7,  # 用于解析和操作HTML文档的库，可能被用来在恶意代码中篡改或注入内容。
    },
    "FunctionCalls": {
        "viper.GetString": 6,  # 从配置文件获取字符串值，配置文件被篡改可能导致程序行为异常。
        "sess.Exec": 9,  # 执行数据库操作的函数，可能导致SQL注入攻击。
        "sess.Collection('mark')": 7,  # 访问数据库集合的调用，可能被用于访问或篡改敏感信息。
        "sess.Exec('DROP TABLE IF EXISTS mark')": 9,  # 删除数据库表的调用，如果权限控制不当可能导致数据丢失。
        "template.ParseFiles": 6,  # 解析模板文件，可能被恶意代码用于动态内容生成或文件注入。
        "regexp.MustCompile": 5,  # 编译正则表达式，可能用于查找和替换特定内容。
        "goquery.NewDocumentFromReader": 7,  # 解析HTML文档，可能用于篡改或注入恶意HTML内容。
        "doc.Find('body')": 7,  # 查找HTML文档中的body标签，可能被用来注入恶意脚本。
        "colly.NewCollector": 7,  # 创建新的爬虫实例，可能用于恶意爬取数据。
    },
    "Strings": {
        "StatusTemporaryRedirect": 6,  # HTTP状态码，用于重定向，可能被恶意代码用来引导用户到恶意网站。
        "Content-Type": 5,  # HTTP头部，控制响应类型，可能被用来伪装响应内容。
        "Content-Length": 5,  # HTTP头部，表示内容长度，可能被用来操控HTTP响应。
        "input[type=password]": 8,  # 查找密码字段，可能用于提取或窃取密码。
        "action=\"/phish.php\"": 8,  # 将HTML表单的action属性修改为指向phish.php，明显的钓鱼行为。
    }
}

#载荷的特征模式
suspicious_features = {
    "Imports": {
        "archive/zip": 3,  # 中等，压缩文件的处理可能用于提取潜在的恶意负载。
        "github.com/spencercw/go-xz": 5,  # 中等，处理XZ压缩数据，可能用于解压和处理恶意负载。
        "github.com/ssut/payload-dumper-go/chromeos_update_engine": 6,  # 高，处理特定的固件更新格式，可能涉及恶意固件或数据的操作。
        "compress/bzip2": 5,  # 中等，处理BZIP2压缩数据，可能用于解压和处理恶意负载。
        "crypto/sha256": 4,  # 中等，计算SHA-256哈希，用于数据完整性检查，可能用于验证恶意数据。
    },
    "Function Calls": {
        "zip.OpenReader": 6,  # 高，处理ZIP文件中的文件，可能用于提取隐藏的恶意负载。
        "payload.Open": 6,  # 高，加载和初始化负载，可能涉及恶意操作。
        "payload.ExtractSelected": 6,  # 高，提取选定的数据，可能用于提取和操作恶意数据。
        "payload.ExtractAll": 6,  # 高，提取所有数据，可能涉及恶意数据的全面操作。
        "xz.NewDecompressionReader": 5,  # 中等，处理XZ压缩数据，可能用于解压恶意负载。
        "bzip2.NewReader": 5,  # 中等，处理BZIP2压缩数据，可能用于解压恶意负载。
    },
    "Strings": {
        "payload.bin": 6,  # 高，特定的文件名，可能涉及加载或提取恶意负载。
        "extracted_": 4,  # 中等，生成的输出目录前缀，可能涉及恶意数据存储。
        "payload.bin": 6,  # 高，特定的文件名，可能涉及加载或提取恶意负载。
        ".xz": 5,  # 中等，XZ压缩格式，可能用于处理和解压恶意负载。
        ".bz2": 5,  # 中等，BZIP2压缩格式，可能用于处理和解压恶意负载。
        "CrAU": 4,  # 中等，特定的标识符，可能用于检测恶意负载的格式。
    }
}