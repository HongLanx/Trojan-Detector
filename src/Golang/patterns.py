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

botnet_patterns = {
    "Imports": {
        "github/google/gopacket": 5,  # 专门用于网络数据包处理，常见于需要制造或分析网络流量的恶意软件
        "github/google/gopacket/layers": 5,  # 网络层操作库，同上，用于构造或解析不同网络层的数据
        "darkangel/server/client": 9,  # 特定的僵尸网络客户端库，高度特定于恶意软件
        "darkangel/server/constant": 9, # 特定的常量库，用于僵尸网络，同样高度特定于恶意软件
        "google.golang.org/grpc": 3,  # gRPC库，高效通信，可能用于复杂的恶意软件
        "google.golang.org/grpc/credentials": 2,  # gRPC的凭证管理
        "github.com/Xart3mis/AKILT/Client/lib/DOS/httpflood": 6,  # HTTP洪水攻击库
        "github.com/Xart3mis/AKILT/Client/lib/DOS/slowloris": 6,  # Slowloris攻击库
        "github.com/Xart3mis/AKILT/Client/lib/DOS/udpflood": 6,  # UDP洪水攻击库
        "github.com/Xart3mis/AKILT/Client/lib/keylogger": 7,  # 键盘记录库，明确用于监控用户输入
        "github.com/Xart3mis/AKILT/Client/lib/reg": 6,  # 可能用于注册表操作
        "github.com/Xart3mis/AKILT/Client/lib/webcam": 7,  # Webcam访问库，用于捕获视频
        "github.com/vova616/screenshot": 6,  # 屏幕截图库，用于捕获屏幕图像
        "golang.design/x/hotkey": 6  # 热键库，用于监听键盘快捷键
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
        "enc.Encode": 5 , # 执行数据编码，用于准备发送到控制服务器的数据
        "lis.Accept": 3,  # 接受网络连接，用于服务器或客户端应用
        "grpc.NewServer": 2,  # 创建gRPC服务器，用于构建服务端应用
        "pb.RegisterConsumerServer": 1,  # 在gRPC上注册服务，用于服务端
        "s.Serve": 1,  # 启动gRPC服务，用于服务端操作
        "syscall.LoadLibrary": 4,  # 加载动态链接库，用于访问系统底层API
        "syscall.GetProcAddress": 4,  # 获取函数地址，用于调用系统API
        "keylogger.Run": 7,  # 运行键盘记录，用于监控用户输入
        "exec.Command": 2,  # 执行系统命令，用于执行远程命令或脚本
        "os.OpenFile": 2,  # 打开文件，用于读写文件
    },
    "Strings": {
        "Infected by exploit": 9,  # 明确指示设备被感染，高度特异性
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
        "flood": 5,  # 执行网络洪水攻击，特定于DDoS
    }
}
