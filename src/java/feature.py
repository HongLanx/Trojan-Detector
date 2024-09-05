# 加密器的特征模式
encryption_patterns = {
    "Imports": {
        "java.security.SecureRandom": 6,  # 用于生成不可预测的随机数，常见于混淆或恶意行为中。
    },
    "FunctionCalls": {
        "Caesium.getRandom": 6,  # 获取随机数生成器，用于生成随机数据，可能用于混淆或恶意行为。
        "Cipher.getInstance(Instance)": 6,  # 获取加密算法的实例。
        "CryptoRansomware.GenKey()": 6,  # 生成 AES 密钥。
        "CryptoRansomware.EncryptFile(filein, fileout, aesKey)": 6,  # 加密文件。
        "CryptoRansomware.DecryptFile(fileout, filein, aesKey)": 6,  # 解密文件。
    },
    "Strings": {
        "Unsupported": 5,  # 用于生成随机名称的一部分，可能涉及混淆或生成无用的代码。
        "EncryptedWithKey": 6,  # 加密数据的标记。
    }
}

# 僵尸网络特征模式
botnet_patterns = {
    "Imports": {
        "android.spyware.receivers.ExfiltrateZombieR": 9,  # 包名包含 "spyware"，接收器类 ExfiltrateZombieR 可能用于恶意数据提取。
        "android.spyware.model.Zombie": 9,  # 类名带有恶意意图，"Zombie"可能代表受控的恶意设备。
    },
    "FunctionCalls": {
        "Harvester.getZombie": 8,  # 该方法名暗示获取某种恶意对象（"Zombie"），通常用于控制或监控受感染设备。
        "Socket.connect": 6,  # 连接到远程控制服务器。
        "ServerSocket.accept": 6,  # 接受来自僵尸网络的连接。
    },
    "Strings": {
        "Zombie.toJSON": 6,  # 将恶意对象序列化为JSON格式，通常用于数据传输到远程服务器。
        "botnet": 6,  # 关键字，可能用于标记僵尸网络相关的代码。
    }
}

# 渗透测试的特征模式
penetration_patterns = {
    "Imports": {
        "com.google.protobuf.ByteString": 7,  # 用于处理和转换数据，可能涉及敏感数据的隐蔽存储和传输。
        "com.google.protobuf.InvalidProtocolBufferException": 6,  # 用于处理协议缓冲区的异常情况，涉及数据解析的健壮性。
        "com.qingyou.qynat.client.client.TcpConnection": 7,  # TcpConnection 处理网络连接，可能用于建立恶意的网络通信。
        "com.qingyou.qynat.commom.codec.NatProtoCodec": 7,  # 自定义编解码器，用于编码和解码网络消息，可能用于隐蔽数据传输。
        "com.qingyou.qynat.commom.exception.QyNatException": 5,  # 自定义异常类，用于处理特定的错误情况，可能用于处理异常状况。
        "com.qingyou.qynat.commom.handler.QyNatCommonHandler": 7,  # 基础处理类，可能被继承并重写以实现恶意功能。
        "com.qingyou.qynat.commom.protocol.proto.NatProto": 7,  # 协议定义类，可能包含自定义的消息类型和数据结构。
    },
    "FunctionCalls": {
        "new QyNatClient().connect": 7,  # 创建连接，可能涉及到网络通信和远程服务器操作，潜在恶意用途。
        "createNatMessage": 7,  # 创建消息对象的函数，涉及构造自定义协议数据，可能用于隐蔽的数据传输。
        "handleConnected": 7,  # 处理连接建立的方法，涉及建立新的网络连接，可能用于恶意目的。
        "initChannel": 7,  # 用于初始化网络通道的函数，可能配置了恶意的处理链。
        "downloadFileFromURL": 7,  # 下载文件的关键函数，涉及从 URL 下载文件，可能会下载恶意文件
        "loadUrl": 7,  # 加载指定 URL，关键点在于 URL 的内容是否安全
        "HttpClient.execute": 6,  # 执行 HTTP 请求，可能用于探测服务。
    },
    "Strings": {
        "new QyNatService(properties)": 6,  # 创建服务实例，潜在风险取决于 `QyNatService` 的实现。
        "qyNatService.connect": 6,  # 调用服务的 `connect` 方法，潜在风险取决于 `QyNatService` 的实
        "NatProtoCodec.decode": 7,  # 使用自定义解码器解码数据，涉及自定义协议，可能用于隐蔽的数据传输。
        "DEFAULT_DOWNLOAD_URL": 7,  # 默认下载 URL 的字符串，可能下载恶意文件
        "vulnerability": 6,  # 可能用于标记漏洞。
    }
}

# 代码混淆的特征模式
obfuscation_patterns = {
    "Imports": {
        "import net.md_5.specialsource.JarRemapper": 5,  # JarRemapper类，用于重映射类名和包名，可能涉及混淆或重命名操作
        "import org.objectweb.asm.Attribute": 4,  # ASM库中的Attribute类，用于字节码属性操作
        "import dev.sim0n.caesium.mutator.impl.*": 5,  # 导入所有混淆器实现类，涉及多种混淆策略
        "import dev.sim0n.caesium.mutator.impl.crasher.BadAnnotationMutator": 6,  # 破坏注解的混淆器，可能用于使类失效
        "import dev.sim0n.caesium.mutator.ClassMutator": 5,  # Caesium库中的抽象类，用于定义混淆变异器
        "import org.objectweb.asm.tree.ClassNode": 6,  # ASM 库的一部分，用于表示类的结构信息，可能用于恶意字节码操作。
        "import org.objectweb.asm.Opcodes": 6,  # ASM 框架的一部分，用于字节码操作，表明有可能对类文件进行修改。
        "import dev.sim0n.caesium.Caesium": 6,  # 主要用于获取实例和操作全局状态，可能用于管理恶意行为。
        "import dev.sim0n.caesium.exception.CaesiumException": 6,  # 自定义异常，通常用于处理特定的错误，可能涉及隐藏的错误处理。
        "import dev.sim0n.caesium.mutator.impl.ClassFolderMutator": 6,  # 处理类文件的变异，可能涉及代码的隐蔽性修改。
        "import dev.sim0n.caesium.mutator.impl.crasher.ImageCrashMutator": 6,  # 处理类文件的崩溃，可能用于恶意操作。
        "import dev.sim0n.caesium.util.ByteUtil": 6,  # 工具类，用于处理字节数据，可能涉及数据的隐蔽处理。
        "import dev.sim0n.caesium.util.wrapper.impl.ClassWrapper": 6,  # 封装类，用于操作和修改类节点，涉及潜在的恶意变异。
    },
    "FunctionCalls": {
        "jar.getNode": 5,  # 从JAR文件中获取类节点（ClassNode），涉及字节码或类结构操作，可能用于分析或修改类
        "JarRemapper.map": 5,  # 通过JarRemapper重映射类名，可能用于改变类结构以适应新的环境或避免检测
        "JarRemapper.mapFieldName": 5,  # 通过JarRemapper重映射字段名称，可能用于隐藏或改变字段的实际用途
        "JarRemapper.mapMethodName": 5,  # 通过JarRemapper重映射方法名称，可能用于混淆代码或隐藏实际的功能调用
        "MavenShade.transformClassName": 5,  # 根据重定位规则转换类名，可能用于代码混淆或类名重命名
        "JarRemapper.mapTypeName": 5,  # 重映射类型名称，可能用于重命名或混淆类名和包名
        "SpecialSource.verbose": 4,  # 检查是否启用了详细输出，可能用于调试或记录操作
        "mutatorManager.getMutator": 5,  # 获取混淆器中的具体变异器，涉及混淆操作
        "imageCrashMutator.ifPresent": 5,  # 检查图像崩溃变异器是否存在并应用，
        "mutatorManager.handleMutation": 5,  # 处理类的混淆操作，
        "Caesium.getInstance": 5,  # 获取混淆器实例，明确用于代码混淆操作，具有较高可疑性。
        "mutators.add(new ClassFolderMutator())": 6,  # 添加混淆器，将类转换为文件夹，具有较高可疑性。
        "mutators.add(new ImageCrashMutator())": 6,  # 添加混淆器，生成导致程序崩溃的类，具有较高可疑性。
        "mutators.add(new BadAnnotationMutator())": 6,  # 添加混淆器，破坏注解，可能导致类失效，具有较高可疑性。
        "mutators.add(new ShuffleMutator())": 5,  # 添加混淆器，重新排列类成员，具有较高可疑性。
        "mutators.add(new TrimMutator())": 5,  # 添加混淆器，可能用于移除类的无用部分，具有较高可疑性。
        "mutators.add(new LineNumberMutator())": 5,  # 添加混淆器，改变代码行号信息，具有较高可疑性。
        "mutators.add(new LocalVariableMutator())": 5,  # 添加混淆器，改变局部变量信息，具有较高可疑性。
        "mutators.add(new StringMutator())": 5,  # 添加混淆器，混淆字符串信息，具有较高可疑性。
        "mutators.add(new ControlFlowMutator())": 5,  # 添加混淆器，改变控制流，具有较高可疑性。
        "mutators.add(new NumberMutator())": 5,  # 添加混淆器，改变数值信息，具有较高可疑性。
        "mutators.add(new PolymorphMutator())": 5,  # 添加混淆器，可能用于引入多态性混淆，具有较高可疑性。
        "mutators.add(new ReferenceMutator())": 5,  # 添加混淆器，改变类或方法引用，具有较高可疑性。

    },
    "Strings": {
        "(new Object() {": 5,  # 匿名类的创建，用于生成混淆后的字符串
        "Obfuscated-By: Caesium": 5,  # 表示文件被混淆器Caesium处理过，明确表示混淆操作
        "ShuffleMutator, TrimMutator, LineNumberMutator, LocalVariableMutator, StringMutator, ControlFlowMutator, NumberMutator, PolymorphMutator, ReferenceMutator": 5,  # 各种混淆器的名称
    }
}

# 钓鱼攻击的特征模式
phishing_patterns = {
    "Imports": {
       "import javax.net.ssl.HostnameVerifier": 4,  # 用于验证主机名，可能用于绕过SSL验证
       "android.spyware.utils.Harvester": 8,  # 类名暗示用于收集数据或资源，通常与恶意行为相关。

    },
    "FunctionCalls": {
       "webview1.setWebViewClient": 5,  # 设置自定义WebViewClient，结合上下文可疑性较高，可能用于拦截和操作网页内容
       "webview1.evaluateJavascript": 6,  # 执行JavaScript代码，可能用于注入恶意脚本，存在较高可疑性
       "webView.addJavascriptInterface": 6,  # 添加与WebView交互的接口，可能用于从网页中获取敏感信息，存在较高可疑性。
       "r.startRequestNetwork": 5,  # 开始网络请求
       "webView.addJavascriptInterface(new WebAppInterface(this), \"Android\")": 6,  # 将JavaScript接口绑定到WebView中，可能用于截获用户数据，存在较高可疑性
       "r.setParams": 5,  # 设置网络请求参数
       "SSLSocketFactory": 4,  # 创建SSL套接字工厂，可能用于自定义SSL行为
       "Harvester.getEmailAdresses": 8,  # 获取用户的电子邮件地址，恶意软件常用于数据窃取。
       "JOptionPane.showMessageDialog": 5  # 显示错误信息提示窗口，可能用于社会工程学攻击，欺骗用户操作。
    },
    "Strings": {
        "https://www.instagram.com/": 6,  # 目标URL，结合代码意图可能用于抓取社交媒体用户数据
        "Save Your Login Info?": 5,  # 判断是否保存登录信息，可能用于判断用户是否登录，存在一定可疑性。
        "YOUR_SERVER_URL": 5,  # 服务器地址变量，可能用于发送抓取的数据，存在一定可疑性。
        "phishing": 5,  # 钓鱼攻击标记。
    }
}

# 载荷的特征模式
payload_patterns = {
"Imports": {
        "java.io.BufferedInputStream": 6,  # 用于读取 URL 的输入流。
        "java.net.URL": 6,  # 处理 URL 操作。
        "java.util.zip.ZipEntry": 5,  # ZIP 文件条目，用于处理压缩文件中的数据
    },
    "FunctionCalls": {
        "ZipFile": 6,  # 使用 ZipFile 处理 ZIP 文件，这里用于加载和操作 JAR 文件，存在修改或分析的潜在风险。
        "ByteArrayOutputStream.toByteArray": 5,  # 获取内存流的字节数据。
        "FileOutputStream.write": 5,  # 写入文件数据。
        "Runtime.getRuntime().exec(command)": 6,  # 执行命令，可能用于执行恶意载荷。
        "File.createTempFile(UUID.randomUUID().toString(), \".ps1\")": 6,  # 创建临时 PowerShell 文件。
        "new SearchDirectory(this.PathtoFind).GetFileMap()": 7,  # 获取文件映射，可能涉及文件操作。
    },
    "Strings": {
        "powershell.exe ": 6,  # PowerShell 执行命令前缀。
        ".ps1": 6,  # PowerShell 脚本扩展名。
    }
}

# 防御绕过的特征模式
Defense_Bypass_patterns = {
"Imports": {
        "android.location.LocationManager": 7,  # 虽然是一个合法的 Android 类，但在恶意软件中用于跟踪用户位置。
        "android.location.LocationListener": 7,  # 同上，用于监听用户位置变化，在恶意软件中常用于监视用户活动。
        "java.lang.reflect.Method": 6,  # 反射操作，可能用于绕过安全机制。
    },
    "FunctionCalls": {
        "ContextCompat.checkSelfPermission": 7,  # 请求敏感权限，可能被恶意软件用于未经用户同意的数据访问。
        "ActivityCompat.requestPermissions": 7,  # 同上，可能用于请求用户不知情的权限。
        "context.sendBroadcast": 7,  # 发送广播意图，可能用于隐秘传输或指令执行。
        "context.startService": 7,  # 启动后台服务，可能用于执行恶意任务。
        "System.getProperty": 6,  # 获取系统属性，如 "sun.boot.class.path"，可能用于收集系统信息。
        "Method.setAccessible(true)": 6,  # 设置方法可访问，用于绕过访问控制。
    },
    "Strings": {
        "reflection": 6,  # 反射相关的操作标记。
    }
}


# 键盘记录器
Keyboard_patterns = {
    "Imports": {
        "import org.jnativehook.GlobalScreen" : 6,   #jnativehook是一个用于捕捉全局键盘和鼠标事件的库，
        "import org.jnativehook.NativeHookException;": 6,  # 通常用于开发键盘记录器或其他类似的系统监控工具。
        "import com.houarizegai.spygen.global.Settings": 5,   # 可能用于访问和管理键盘记录器的配置设置，包名表明代码属于潜在恶意项目的一部分。
        "import org.jnativehook.keyboard.NativeKeyEvent": 6,  # `NativeKeyEvent`用于捕获键盘事件，与键盘记录器的功能直接相关。
        "import org.jnativehook.keyboard.NativeKeyListener": 6,  # `NativeKeyListener`接口用于监听键盘事件，实现键盘记录功能。
        "import com.houarizegai.spygen.global.Utils": 5,  # 可能用于提供一些通用工具函数，包名表明与恶意行为相关。
        "import java.awt.*": 6,  # 包含`Robot`类，用于捕获屏幕内容，在截图功能中常用，但结合上下文可能用于隐秘监控。
    },
    "FunctionCalls": {
        "startKeylogger": 6,  #startKeylogger方法，用于启动键盘记录器。
        "GlobalScreen.registerNativeHook": 8, #注册了一个全局钩子，允许程序监听系统级别的键盘事件
        "nativeKeyTyped": 7,  # 此方法捕获并存储键盘输入，是键盘记录器的核心功能之一。
        "onSave": 7,  # 将捕获的键盘输入保存到文件中，这是键盘记录器的一个关键功能。
        "typedCache.append": 6,  # 将捕获的键盘输入添加到缓存中，用于后续保存，显示出记录器的运行机制。
        "cleanFoldersAfterSend": 8,  # 发送邮件后清理文件夹内容，这表明试图隐藏恶意活动，增加了可疑性。
        "Utils.deleteFolderContent": 8,  # 删除文件夹内容，明显表明试图清理记录或证据，极具可疑性。
        "Robot().createScreenCapture": 7,  # 使用`Robot`类捕获屏幕内容，潜在用于监控或记录用户屏幕，增加了可疑性。
        "takePicture": 6,  # 捕捉并保存摄像头图像，有一定可疑性，尤其是在没有用户知情的情况下。

    },
    "Strings": {
        " Keylogger": 5, #这一类名很可能表明该代码是一个键盘记录器
        "Settings.KEYLOGGER_PATH": 8,  # 日志文件路径的设置，结合邮件发送后清理行为，极具可疑性。
        "Settings.WEBCAM_PATH": 8,  # 摄像头数据路径设置，结合清理行为，极具可疑性。
        "Settings.SCREENSHOT_PATH": 8,  # 屏幕截图路径设置，结合清理行为，极具可疑性。
        "WEBCAM_PATH": 5  # 保存摄像头图像的路径

    }
}


# 后门软件
backdoor_patterns = {
    "Imports": {
        "dev.is_a.acaiberii.bakdooro.commands.blatant.blnt": 8,  # 可能涉及到敏感或恶意操作的命令处理
        "dev.is_a.acaiberii.bakdooro.commands.exploit.exploit": 10,  # 可能包含用于执行攻击或恶意操作的代码
        "dev.is_a.acaiberii.bakdooro.game.server": 7,  # 提供对服务器对象的访问，可能用于执行恶意命令
        "dev.is_a.acaiberii.bakdooro.util.handler.chathandler": 7,  # 可能包含处理聊天的逻辑，具体取决于 chathandler 的实现
        "dev.is_a.acaiberii.bakdooro.listeners.chat": 8,  # 可能是恶意的或不可信的自定义类，具体取决于 chat 类的实现
        "dev.is_a.acaiberii.bakdooro.main": 7,  # 可能是恶意的自定义插件类，具体取决于 main 类的实现
        "import rocks.ethanol.ethanolapi.server.connector.EthanolServerConnector": 4,  # 导入服务器连接器类
        "import rocks.ethanol.ethanolapi.EthanolAPI": 4,  # 导入EthanolAPI，可能涉及外部服务器通信和认证
        "import rocks.ethanol.ethanolapi.auth.DiscordAuthURL": 4,  # 导入Discord认证URL类，可能涉及外部服务器认证和信息传递
        "import net.minecraft.client.gui.screen.multiplayer.ConnectScreen": 5,  # 用于连接到多人游戏服务器。与自动连接服务器的功能结合，具有较高的可疑性
    },
    "FunctionCalls": {
        "execute_shell_command": 9,  # 执行传递的命令，具有执行任意命令的潜力，非常危险
        "sendResponse": 8,  # 根据响应代码执行不同的操作，包括执行命令
        "exploit.chatFill": 10,  # 可能用于执行恶意操作，例如填充聊天记录
        "exploit.consoleFill": 10,  # 可能用于执行恶意操作，例如填充控制台日志
        "exploit.remoteOp": 9,  # 可能用于给玩家赋予操作员权限，可能导致权限滥用
        "server.srv.banIP": 8,  # 用于封禁IP，可能被恶意使用
        "server.srv.unbanIP": 8,  # 用于解除封禁IP，可能被恶意使用
        "server.srv.setWhitelist": 8,  # 用于设置白名单，可能影响服务器的安全性
        "server.srv.shutdown": 9,  # 用于关闭服务器，可能导致服务中断
        "server.srv.getPluginManager().disablePlugin": 8,  # 用于禁用插件，可能导致插件功能被破坏
        "blnt.infoBox": 7,  # 可能用于显示通知或警告，具体取决于实现
        "misc.Floppa": 6,  # 未知功能，具体取决于实现
        "itm.hacks": 7,  # 包含一系列可能与作弊或恶意行为相关的字符串
        "HSDAttack": 8,  # 函数名称暗示可能的攻击行为，具体实现不明，可能包含恶意操作
        "modExp": 7,  # 方法名称暗示可能用于加密解密操作，需检查其实现是否包含恶意行为
        "HSDProtect": 8,  # 方法名称暗示保护操作，可能用于隐藏恶意行为的保护机制，需检查具体实现
        "HSDKeyGenerator": 7,  # 实现了复杂的密钥生成算法，涉及许多随机生成和数学操作，可能用于隐藏恶意目的或后门
        "NbtCompound.putString": 4,  # 将字符串数据存储到NBT（命名二进制标签）结构中
        "NbtCompound.getString": 4,  # 从NBT结构中读取字符串数据
        "EthanolAPI.connect": 4,  # 使用授权密钥连接到外部API，可能涉及敏感信息的传输
        "connector.listen": 4,  # 监听服务器消息
        "EthanolAPI.DEFAULT_AUTHENTICATOR.getUrl": 4,  # 获取Discord认证URL，涉及外部认证流程
        "EthanolAPI.DEFAULT_AUTHENTICATOR.authenticateAsync": 4,  # 异步进行Discord认证
        "MinecraftClient.getInstance().keyboard.getClipboard": 6,  # 获取剪贴板内容。结合自动连接服务器的功能，可能涉及隐私或安全问题
        "ConnectScreen.connect": 6,  # 连接到指定服务器，涉及服务器连接操作，可能被用于未经授权的远程连接
        "ServerAddress.parse": 5,  # 解析服务器地址字符串。结合自动连接服务器的功能，可能被用于隐私或安全问题
        "XposedBridge.hookAllMethods": 7,  # hook所有方法，可能用于广泛的行为修改
    },
    "Strings": {
        "exec/": 9,  # 在请求中搜索此标识符来执行命令，通常是远程代码执行攻击的标志
        ">fill": 10,  # 可能触发填充聊天或控制台的恶意操作
        ">op": 9,  # 可能赋予玩家操作员权限，涉及权限提升
        ">deop": 9,  # 可能移除玩家操作员权限，涉及权限管理
        ">ban": 8,  # 可能封禁玩家IP，涉及权限管理
        ">unban": 8,  # 可能解除玩家IP封禁，涉及权限管理
        ">chat": 6,  # 控制聊天功能的开关，可能影响服务器的聊天功能
        ">whitelist": 8,  # 控制白名单功能，可能影响服务器的访问控制
        ">server": 9,  # 控制服务器的操作，可能导致服务器关闭
        ">plugin": 8,  # 控制插件的启用或禁用，可能破坏服务器功能
        ">blatant": 8,  # 可能触发恶意操作，例如显示恶意通知
        "handler": 7,  # 调用 chathandler 的 handler 方法，具体取决于 chathandler 的实现
        "RSA BACKDOOR CONNECTOR": 8,  # 明确提到“backdoor”，表明可能存在恶意用途
        "Backdoor connected!": 8,  # 明确提到“backdoor”，表明可能存在恶意用途
        "Private key has been saved to folder": 8,  # 提到私钥的保存，可能与未经授权的访问相关
        "dev.is_a.acaiberii.bakdooro.game": 7,  # 可能是恶意或不可信的包名
        "chat": 8,  # 不清楚 chat 类的实现，如果它处理不安全的输入或执行恶意操作，则可能是恶意的
        "Fly": 9,  # 这些字符串表明可能涉及作弊工具或恶意功能
        "KillAura": 9,  # 这些字符串表明可能涉及作弊工具或恶意功能
        "Speed": 9,  # 这些字符串表明可能涉及作弊工具或恶意功能
        "FastInteract": 9,  # 这些字符串表明可能涉及作弊工具或恶意功能
        "BadPacket": 9,  # 这些字符串表明可能涉及网络攻击或恶意功能
        "Backdoor": 10,  # 这些字符串表明可能涉及后门功能，极高风险
        "DDoS": 10,  # 这些字符串表明可能涉及分布式拒绝服务攻击，极高风险
        "SlowPacket": 9,  # 这些字符串表明可能涉及网络攻击或恶意功能
        "Anticheat Bypass": 9,  # 这些字符串表明可能涉及绕过反作弊机制，极高风险
        "apiKey": 4,  # API密钥字段，存储敏感信息，具有一定的可疑性
        "Clipboard Connect": 5,  # 按钮文本，用于从剪贴板连接服务器
    }
}

# 勒索软件
ransomware_patterns = {
"Imports": {
        "java.nio.file.Files": 6,  # 处理文件操作，可能用于加密和锁定文件。
        "javax.crypto.*": 7,  # 包含加密、解密相关类。
        "javax.crypto.spec.SecretKeySpec": 6,  # 用于指定加密算法的密钥。
        "java.security.GeneralSecurityException": 7,  # 安全相关的异常类。
    },
    "FunctionCalls": {
        "Files.write": 6,  # 写入加密文件。
        "CryptoRansomware.GenKey()": 6,  # 生成 AES 密钥。
        "CryptoRansomware.EncryptFile(filein, fileout, aesKey)": 6,  # 加密文件。
        "CryptoRansomware.DecryptFile(fileout, filein, aesKey)": 6,  # 解密文件。
        "EmbeddedDatabase.InsertRecordIntoTable(containsFilters, CryptoRansomware.RetrieveEncryptedAesKey(pubkey, aesKey))": 6,  # 插入记录到数据库。
        "EmbeddedDatabase.GetMapFromTable()": 6,  # 从数据库获取映射。
        "CryptoRansomware.RetrieveAesKey(privKey)": 7,  # 从数据库检索 AES 密钥。
    },
    "Strings": {
        "ransom": 6,  # 勒索标记。
        "decrypt": 6,  # 解密标记。
        "RansomwareException": 5,  # 自定义异常类，可能用于标记勒索软件的特征。
    }
}


#木马  特征模式
Trojan_virus_patterns = {
    "Imports": {

    },
    "FunctionCalls": {
        "exeFileTerminator": 6,  # 该函数用于删除带有`.exe`扩展名的文件，具有较高的可疑性
        "DeleteFile": 6,  # 删除文件操作
        "Obj.delete": 6,  # 直接删除文件，具有较高可疑性
        "PathRetuner": 5,  # 递归遍历文件夹并删除文件
        "FileDeleter.exeFileTerminator": 6,  # 调用删除可执行文件的方法
    },
    "Strings": {
        "exe.": 6,  # 用于检测可执行文件的扩展名

    }
}

#根套件的特征模式
rootkit_patterns = {
    "Imports": {

    },
    "FunctionCalls": {
        "Runtime.getRuntime().exec": 9,  # 执行系统命令，具有显著的恶意潜力，可以执行任意命令
        "URLEncoder.encode": 7,  # 对 URL 参数进行编码，可能用于构造恶意请求以绕过过滤
    },
    "Strings": {
        "Runtime.getRuntime().exec": 9,  # 可能被用于执行恶意命令
        "../../../../../etc/passwd": 9,  # 目录遍历攻击，试图访问敏感文件
        "rm": 9,  # 用于删除文件的命令，具有明显的破坏性
        "sample-to-delete": 8,  # 要删除的文件名，用于测试删除操作

    }
}

# 杀毒软件
antivirus_patterns = {
    "Imports": {
        "java.io.ObjectOutputStream": 7,  # 用于将对象通过网络发送，可能用于发送加密密钥或恶意命令。
        "java.net.ServerSocket": 7,  # 用于监听和接受网络连接，可能被用于建立命令和控制服务器。
        "java.security.KeyPair": 6,  # 用于生成公钥和私钥对，可能用于加密恶意通信。
        "java.security.KeyPairGenerator": 6,  # 用于创建密钥对生成器，生成RSA密钥对，用于加密和解密操作。
        "java.security.PrivateKey": 6,  # 私钥对象，可能用于解密从客户端接收到的加密数据。
        "java.security.PublicKey": 6,  # 公钥对象，可能用于加密发送到客户端的数据。
        "java.security.NoSuchAlgorithmException": 6,  # 用于处理加密算法不可用的异常，确保密钥生成操作顺利进行。
        "java.security.SecureRandom": 7,  # 生成加密所需的随机数，确保加密过程的安全性。
        "javax.crypto.Cipher": 9,  # 实现文件的加密和解密操作，AES和RSA加密核心组件。
        "java.net.Socket": 8,  # 与C&C服务器进行网络通信，传输加密密钥或接收解密密钥。
        "java.nio.file.Files": 7,  # 读取和写入文件内容，可能涉及到加密后的文件写入或解密文件的读取。
    },
    "FunctionCalls": {
        "createRSAKeyPair": 6,  # 用于生成RSA公钥和私钥对，可能用于保护恶意通信。
        "ServerSocket.accept": 7,  # 等待客户端连接，可能用于接收从客户端发来的命令或数据。
        "ObjectOutputStream.writeObject": 7,  # 将对象通过网络发送，可能用于发送加密的恶意命令或密钥。
        "Socket.getOutputStream": 6,  # 获取输出流，用于发送数据到客户端，可能用于恶意通信。
        "KeyPairGenerator.getInstance": 6,  # 获取RSA算法的实例，用于生成密钥对。
        "System.exit": 5,  # 在发生错误时退出程序，可能用于规避检测。
        "KeyPairGenerator.initialize": 6,  # 初始化密钥对生成器，设置密钥的大小。
        "KeyPairGenerator.generateKeyPair": 6,  # 生成公钥和私钥对，可能用于加密和解密通信。
        "getAllFiles": 8,  # 递归遍历目标目录下的所有文件，用于确定需要加密的文件集合。
        "encryptFiles": 9,  # 执行文件的加密操作，核心功能，用AES对目标文件进行加密。
        "decryptFiles": 9,  # 执行文件的解密操作，还原被加密的文件，模拟支付赎金后的解密过程。
        "createAESCipher": 8,  # 初始化AES加密对象，确保加密操作可以顺利进行。
        "createRSACipher": 8,  # 初始化RSA加密对象，用于加密AES密钥，确保密钥传输的安全性。
        "placeRansomNote": 7,  # 在目标目录中放置勒索信息，告知用户文件已被加密。
        "deleteOriginals": 7,  # 删除原始的未加密文件，确保用户无法恢复数据而必须支付赎金。
        "startWaiting": 6,  # 设置延迟，模拟勒索软件等待赎金支付前的时间段。
        "getRSAPublicKey": 7,  # 从C&C服务器获取公钥，用于加密AES密钥，确保密钥的保密性。
        "getRSAPrivateKey": 7,  # 从C&C服务器获取私钥，用于解密AES密钥，模拟支付赎金后恢复文件的过程
    },
    "Strings": {
        "http://malicious-site.com": 9,  # 可能用于与C&C服务器通信，接收指令或传送加密密钥。
        "C:\\Users\\": 8,  # 指向特定用户目录，可能是勒索软件加密的目标目录。
        "C:\\Windows\\System32\\": 8,  # 系统目录路径，可能涉及操作系统的关键文件或引导程序。
        "cmd.exe /c del ": 7,  # 用于删除文件的命令，可能被用来销毁原始文件或清理痕迹。
        "shutdown -r -t 0": 7,  # 强制重启系统命令，可能用于让用户看到勒索信息或加密状态。
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn": 9,  # 可能是RSA公钥的片段，用于加密对称密钥。
        "Your files have been encrypted": 10,  # 勒索信内容，告知用户文件被加密并要求支付赎金。
        "How to recover your files": 10,  # 勒索信标题，通常包含支付赎金和获取解密密钥的指导。
        "AES256": 8,  # 指定加密算法（AES-256），暗示文件被该算法加密。
        "RSA2048": 8,  # 指定加密算法（RSA-2048），通常用于加密AES密钥。
        "192.168.1.1": 6,  # 内部网络地址，可能与C&C服务器通信有关。

    }
}

# 广告软件 特征模式
adware_patterns = {
    "Imports": {
        "java.net.HttpURLConnection": 6,  # 可能被用于发送窃取的数据或从远程服务器接收恶意指令
        "com.google.android.gms.ads.AdListener": 3,  # 广告加载监听器，通常用于合法的广告管理，但如果被滥用，可能用于不受欢迎的广告显示。
        "com.google.android.gms.ads.AdRequest.Builder": 3,  # 用于创建广告请求，通常无害，但可能被滥用用于频繁广告请求。
        "com.google.android.gms.ads.AdSize": 2,  # 用于设置广告的尺寸，通常无害。
        "com.google.android.gms.ads.AdView": 3,  # 用于显示横幅广告，通常无害，但频繁使用可能影响用户体验。
        "com.google.android.gms.ads.InterstitialAd": 4,  # 用于显示插页式广告，可能会打断用户体验，特别是如果频繁弹出。
        "com.google.android.gms.ads.MobileAds": 3,  # 初始化广告SDK，通常无害，但可能用于启动不受欢迎的广告服务。
        "com.google.android.gms.ads.NativeExpressAdView": 3,  # 用于显示本地广告，通常无害，但频繁使用可能影响用户体验。
        "android.os.AsyncTask": 4,  # 用于在后台线程中执行任务，可能被滥用进行隐蔽操作。
    },
    "FunctionCalls": {
        "doInBackground": 6,  # 在后台解析网页，可能隐藏恶意操作，例如数据抓取。
        "onPostExecute": 5,  # 在任务完成后执行，可能用于处理和执行从服务器抓取的命令。
        "InterstitialAd.show": 5,  # 显示插页式广告，可能会打断用户体验，尤其是在不合适的时间点频繁调用时。
        "catkeyvaencode": 6,  # 涉及字符串处理，可能用于加密或混淆数据。
        "randomString": 6,  # 用于生成随机字符串，可能用于生成加密密钥或混淆数据。
        "setAdListener": 6,  # 为广告对象设置事件监听器，监听广告加载、点击、展示等事件。
        "loadAd": 5,  # 加载广告内容，可能涉及广告的预加载和展示，通常与广告展示逻辑相关。
    },
    "Strings": {
        "onAdFailedToLoad": 3,  # 广告加载失败的回调，通常无害，但可能会用于调试或监控广告加载情况。
        "paramContext.show()": 5,  # 插页式广告展示，可能用于频繁打断用户，影响用户体验。
        "market://details?id=": 4,  # 用于启动Google Play商店，可能用于推广或下载应用。
        "https://play.google.com/store/apps/details?id=": 4  # 用于启动Google Play商店的Web链接，可能用于推广或下载应用。

    }
}

# 黑客工具特征模式
hackingtool_patterns = {
    "Imports": {
        "my.app.client.ClientListener": 6,  # 自定义监听器，可能用于远程控制或数据传输。
        "android.provider.CallLog": 4,  # 访问设备的通话记录日志，涉及隐私数据，有潜在的恶意用途。
        "android.provider.ContactsContract": 5,  # 访问设备的联系人数据，涉及隐私信息，有潜在的恶意用途。
        "android.telephony.SmsMessage": 5,  # 用于处理短信信息，涉及隐私数据读取，可能存在恶意用途。
        "android.content.BroadcastReceiver": 4,  # 广播接收器用于响应系统事件，如启动、短信接收等，可能用于监听或自动启动，涉及潜在风险。
        "android.location.LocationListener": 4,  # 监听位置变化，涉及对用户位置信息的访问，存在隐私风险
        "Packet.FilePacket": 5,  # 自定义数据包，可能用于封装和发送敏感数据。
        "android.telephony.TelephonyManager": 7,  # 获取设备和用户的敏感信息，如IMEI、电话号码，隐私风险高。
        "android.hardware.Camera": 7,  # 直接访问摄像头，未经用户许可使用可能涉及严重的隐私侵犯。
        "android.hardware.Camera.PictureCallback": 7,  # 拍照回调，可能用于未授权的照片采集。
        "org.koreops.net.def.beans.AuthCrackParams": 9,  # 提到“AuthCrack”暗示可能涉及破解认证信息，这很可能用于恶意目的。
        "org.koreops.tauro.cli.authtrial.threads.DefaultAuthTrial": 8,  # DefaultAuthTrial可能与未经授权的访问尝试或破解过程相关。
        "org.koreops.tauro.cli.dao.UpdaterDao": 7,  # UpdaterDao可能被用于与远程服务器通信，执行未经授权的更新操作。
        "org.koreops.tauro.cli.scraper.AbstractScraperAndSaver": 8,  # AbstractScraperAndSaver通常与数据抓取和保存相关，可能用于收集敏感信息。
        "org.jsoup.Jsoup": 6,  # Jsoup库通常用于解析HTML页面，这在恶意软件中可能用于数据抓取或信息收集。
    },
    "FunctionCalls": {
        "setPhoneNumber": 5,  # 设置或收集电话号码，涉及隐私数据，有潜在的恶意用途。
        "new FileInputStream(f)": 6,  # 打开文件输入流，可能用于读取用户敏感文件。
        "ctx.handleData(channel, packet.build())": 7,  # 处理并发送数据，可能用于数据 exfiltration。
        "setIMEI": 5,  # 设置或收集设备IMEI，涉及隐私数据，有潜在的恶意用途。
        "query()": 4,  # 用于从内容提供者（如通话记录）中查询数据，涉及隐私数据的读取，有潜在的恶意用途。
        "ContentResolver.query()": 5,  # 用于从内容提供者查询数据，涉及隐私数据的读取，有潜在的恶意用途。
        "context.startService()": 7,  # 启动服务的调用，多次出现，可能用于在后台执行一些未授权的操作。
        "onPictureTaken": 8,  # 获取拍照后的图像数据，可能用于未授权的数据传输，涉及隐私风险
        "takePhoto": 7,  # 未经用户同意执行拍照操作，可能被用于恶意目的
        "cam.startPreview": 4,  # 启动摄像头预览，可能与未经授权的拍照操作有关
        "cam.takePicture": 8,  # 实际执行拍照操作，可能未经用户同意，涉及隐私问题
        "tm.getLine1Number()": 8,  # 获取用户电话号码，涉及高隐私风险。
        "tm.getDeviceId()": 9,  # 获取设备唯一标识符（IMEI），高度敏感且隐私风险极高。
        "tm.getNetworkCountryIso()": 6,  # 获取网络国家代码，可能用于地理定位。
        "tm.getNetworkOperatorName()": 6,  # 获取网络运营商名称，可能用于识别用户位置。
        "tm.getSimCountryIso()": 6,  # 获取SIM卡国家代码，可能用于地理定位。
        "tm.getSimOperatorName()": 6,  # 获取SIM卡运营商名称，可能用于识别用户位置。
        "tm.getSimSerialNumber()": 8,  # 获取SIM卡序列号，涉及高隐私风险。
        "ctx.getSystemService(Context.TELEPHONY_SERVICE)": 6,  # 获取电话服务，结合其他操作可能用于敏感数据收集。
        "tm.getDeviceSoftwareVersion()": 6,  # 获取设备软件版本，可能用于识别设备特征。
        "cam.startPreview()": 7,  # 启动摄像头预览，可能用于未授权的摄像操作。
        "cam.takePicture(null, null, pic)": 8,  # 拍照操作，可能用于未经授权的数据采集。
        "Jsoup.connect": 7,  # Jsoup的connect方法用于连接远程网页，可能涉及未经授权的数据抓取或通信。
        'header("Authorization", "Basic "': 8,  # 使用Basic认证头可能是为了绕过认证，获取受保护的数据。。
        "UpdaterDao.saveStation": 7,  # 保存数据的方法，可能用于将抓取到的敏感数据存储或发送到远程服务器。
        "Jsoup.connect().timeout().get()": 7,  # 设置超时并获取网页内容，可能用于规避防护机制并抓取数据。
        "scrapeAndLog": 7,  # 该函数名表明该方法会抓取数据并记录日志。结合上下文来看，它可能用于记录从未授权访问的TP-Link路由器中获取的数据，存在较高的恶意风险。
        "logNewTpLinkStation": 8,  # 该函数似乎用于记录新发现的TP-Link路由器站点信息，可能与非法的网络入侵或数据窃取有关，恶意性较高。

    },
    "Strings": {
        "CallLog.Calls.CONTENT_URI": 4,  # 指向通话记录的URI路径，涉及隐私数据的访问。
        "Intent.ACTION_BOOT_COMPLETED": 5,  # 系统启动完成广播，自动启动应用，可能用于保持应用持续运行，有潜在风险。
        "android.provider.Telephony.SMS_RECEIVED": 5,  # 短信接收广播，可能用于拦截或处理短信内容，涉及隐私风险。
        "ConnectivityManager.EXTRA_NETWORK_INFO": 3,  # 网络连接信息，可用于检测网络状态，可能用于监控目的。
        "IMEI": 9,  # IMEI是设备的唯一标识符，获取后可能用于追踪设备
        "PhoneNumber": 8,  # 手机号码涉及用户身份，未经同意获取可能用于恶意目的
        "SimSerial": 7,  # SIM序列号获取可能用于跟踪和识别用户身份
        "getPhoneNumber": 8,  # 获取用户手机号，未经授权存在隐私泄露风险
        "getIMEI": 9,  # 获取设备的IMEI，可能被用于设备追踪
        "wlbasic.htm": 6,  # 特定路由器的无线设置页面，访问这些页面可能用于抓取网络配置或敏感信息。
        "bssid_drv[0] =\"": 7,  # 特定的字符串匹配，用于提取MAC地址，可能涉及网络嗅探或攻击准备。
        "wlsecurity_all.htm": 6,  # 安全配置页面，可能用于抓取WPA/WPA2密钥等敏感信息。
        "dF.pskValue0.value=": 8,  # 提取PSK值（Wi-Fi密钥），显然是为了获取网络访问权限，具有高度的恶意性。
        "Authorization: Basic ": 9,  # 该字符串用于设置HTTP请求头中的认证信息，可能用于未经授权的访问，这种行为通常与恶意代码相关联。
        "Found MAC": 7,  # 该字符串表明程序正在尝试获取并记录MAC地址，可能用于网络入侵或其他恶意行为。
        "Found SSID": 7,  # 该字符串表明程序正在获取并记录SSID信息，这通常与网络嗅探或未经授权的数据收集有关。
        "key": 8,  # 字符串“key”可能表示WEP或WPA密钥，程序试图获取并记录这些信息，明显存在恶意目的
        "Authtype": 7,  # 该字符串表明程序正在获取认证类型，与获取密钥和SSID信息结合使用，可能用于网络入侵。
    }
}

