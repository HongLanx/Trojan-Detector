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
        "encrypt": 6,  # 加密相关，有合法和非法使用
        "AES": 5,  # 加密标准，广泛使用
        "/proc/self/fd/": 8,  # 系统内部路径，可能用于隐藏进程信息
        "key": 5,  # 密钥相关，普遍用途
        "iv": 5,  # 初始化向量，加密过程中常用
        "passwd": 5,  # 密码相关，普遍用途
        "salt": 7,  # 密码盐值，敏感度较高
        "Error encrypting": 8,  # 加密错误，特定场合
        "Error decrypting": 8  # 解密错误，特定场合
    }
}
