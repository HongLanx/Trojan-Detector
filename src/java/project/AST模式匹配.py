import os
import json
from javalang.tree import Node
from javalang.tokenizer import Keyword
import javalang
from javalang.parse import parse
from javalang.tree import Node
from tkinter import Tk
from tkinter.filedialog import askdirectory
from tkinter.filedialog import askopenfilename

# 加载特征库
encryption_patterns = {
    "Imports": {
        "java.security.SecureRandom": 6,
        "javax.crypto.*": 7,
        "javax.crypto.spec.SecretKeySpec": 6,
    },
    "FunctionCalls": {
        "Caesium.getRandom": 6,
        "SecureRandom.getInstanceStrong": 6,
        "Cipher.getInstance(Instance)": 6,
        "CryptoRansomware.GenKey()": 6,
        "CryptoRansomware.EncryptFile(filein, fileout, aesKey)": 6,
        "CryptoRansomware.DecryptFile(fileout, filein, aesKey)": 6,
    },
    "Strings": {
        "Unsupported": 5,
        "EncryptedWithKey": 6,
    }
}

botnet_patterns = {
    "Imports": {
        "android.spyware.receivers.ExfiltrateZombieR": 9,
        "android.spyware.model.Zombie": 9,
        "java.net.Socket": 6,
        "java.net.ServerSocket": 6,
    },
    "FunctionCalls": {
        "Harvester.getZombie": 8,
        "Socket.connect": 6,
        "ServerSocket.accept": 6,
    },
    "Strings": {
        "Zombie.toJSON": 6,
        "botnet": 6,
    }
}

penetration_patterns = {
    "Imports": {
        'com.google.protobuf.ByteString': 7,
        'com.google.protobuf.InvalidProtocolBufferException': 6,
        'com.qingyou.qynat.client.client.TcpConnection': 7,
        'com.qingyou.qynat.commom.codec.NatProtoCodec': 7,
        'com.qingyou.qynat.commom.exception.QyNatException': 5,
        'com.qingyou.qynat.commom.handler.QyNatCommonHandler': 7,
        'com.qingyou.qynat.commom.protocol.proto.NatProto': 7,
        'io.netty.channel.*': 7,
        'java.lang.reflect.*': 8,
        "org.apache.http.client.methods.HttpGet": 6,
        "org.apache.http.client.methods.HttpPost": 6,
    },
    "FunctionCalls": {
        'new QyNatClient().connect': 7,
        'createNatMessage': 7,
        'handleConnected': 7,
        'initChannel': 7,
        'newInstance': 8,
        'downloadFileFromURL': 7,
        'loadUrl': 7,
        "HttpClient.execute": 6,
    },
    "Strings": {
        'new QyNatService(properties)': 6,
        'qyNatService.connect': 6,
        'NatProtoCodec.decode': 7,
        'DEFAULT_DOWNLOAD_URL': 7,
        "vulnerability": 6,
    }
}

# 代码混淆的特征模式
obfuscation_patterns = {
    "Imports": {
        "import net.md_5.specialsource.Jar": 4,
        "import net.md_5.specialsource.JarRemapper": 5,
        "import org.objectweb.asm.Attribute": 4,
        "import dev.sim0n.caesium.mutator.impl.*": 5,
        "import dev.sim0n.caesium.mutator.impl.crasher.BadAnnotationMutator": 6,
        "import dev.sim0n.caesium.mutator.ClassMutator": 5,
        "import org.objectweb.asm.ClassReader": 6,
        "import org.objectweb.asm.tree.ClassNode": 6,
        "import org.objectweb.asm.Opcodes": 6,
        "import dev.sim0n.caesium.Caesium": 6,
        "import dev.sim0n.caesium.exception.CaesiumException": 6,
        "import dev.sim0n.caesium.mutator.impl.ClassFolderMutator": 6,
        "import dev.sim0n.caesium.mutator.impl.crasher.ImageCrashMutator": 6,
        "import dev.sim0n.caesium.util.ByteUtil": 6,
        "import dev.sim0n.caesium.util.wrapper.impl.ClassWrapper": 6,
    },
    "FunctionCalls": {
        "jar.getNode": 5,
        "JarRemapper.map": 5,
        "JarRemapper.mapFieldName": 5,
        "JarRemapper.mapMethodName": 5,
        "MavenShade.transformClassName": 5,
        "JarRemapper.mapTypeName": 5,
        "SpecialSource.verbose": 4,
        "mutatorManager.getMutator": 5,
        "imageCrashMutator.ifPresent": 5,
        "mutatorManager.handleMutation": 5,
        "Caesium.getInstance": 5,
        "mutators.add(new ClassFolderMutator())": 6,
        "mutators.add(new ImageCrashMutator())": 6,
        "mutators.add(new BadAnnotationMutator())": 6,
        "mutators.add(new ShuffleMutator())": 5,
        "mutators.add(new TrimMutator())": 5,
        "mutators.add(new LineNumberMutator())": 5,
        "mutators.add(new LocalVariableMutator())": 5,
        "mutators.add(new StringMutator())": 5,
        "mutators.add(new ControlFlowMutator())": 5,
        "mutators.add(new NumberMutator())": 5,
        "mutators.add(new PolymorphMutator())": 5,
        "mutators.add(new ReferenceMutator())": 5,
    },
    "Strings": {
        "(new Object() {": 5,
        "Obfuscated-By: Caesium": 5,
        "ShuffleMutator, TrimMutator, LineNumberMutator, LocalVariableMutator, StringMutator, ControlFlowMutator, NumberMutator, PolymorphMutator, ReferenceMutator": 5,
    }
}

# 钓鱼攻击的特征模式
phishing_patterns = {
    "Imports": {
       "import android.bluetooth.BluetoothServerSocket": 5,
       "import javax.net.ssl.HostnameVerifier": 4,
       "android.spyware.utils.Harvester": 8,
    },
    "FunctionCalls": {
       "webview1.setWebViewClient": 5,
       "webview1.evaluateJavascript": 6,
       "webView.addJavascriptInterface": 6,
       "r.startRequestNetwork": 5,
       "webView.addJavascriptInterface(new WebAppInterface(this), \"Android\")": 6,
       "r.setParams": 5,
       "SSLSocketFactory": 4,
       "Harvester.getEmailAdresses": 8,
       "JOptionPane.showMessageDialog": 5,
    },
    "Strings": {
        "https://www.instagram.com/": 6,
        "Save Your Login Info?": 5,
        "YOUR_SERVER_URL": 5,
        "phishing": 5,
    }
}

# 键盘记录器的特征模式
keyboard_patterns = {
    "Imports": {
        "import org.jnativehook.GlobalScreen" : 6,
        "import org.jnativehook.NativeHookException;": 6,
        "com.houarizegai.spygen.global.Settings": 5,
        "import org.jnativehook.keyboard.NativeKeyEvent": 6,
        "import org.jnativehook.keyboard.NativeKeyListener": 6,
        "import com.houarizegai.spygen.global.Utils": 5,
        "import java.awt.*": 6,
    },
    "FunctionCalls": {
        "startKeylogger": 6,
        "GlobalScreen.registerNativeHook": 8,
        "nativeKeyTyped": 7,
        "onSave": 7,
        "typedCache.append": 6,
        "attach": 7,
        "send": 7,
        "cleanFoldersAfterSend": 8,
        "Utils.deleteFolderContent": 8,
        "Robot().createScreenCapture": 7,
        "takePicture": 6,
    },
    "Strings": {
        " Keylogger": 5,
        "Settings.KEYLOGGER_PATH": 8,
        "Settings.WEBCAM_PATH": 8,
        "Settings.SCREENSHOT_PATH": 8,
        "WEBCAM_PATH": 5,
    }
}

# 后门软件的特征模式
trojan_patterns = {
    "Imports": {
        'dev.is_a.acaiberii.bakdooro.commands.blatant.blnt': 8,
        'dev.is_a.acaiberii.bakdooro.commands.exploit.exploit': 10,
        'dev.is_a.acaiberii.bakdooro.game.server': 7,
        'dev.is_a.acaiberii.bakdooro.util.handler.chathandler': 7,
        'dev.is_a.acaiberii.bakdooro.listeners.chat': 8,
        'dev.is_a.acaiberii.bakdooro.main': 7,
        "import rocks.ethanol.ethanolapi.server.connector.EthanolServerConnector": 4,
        "import rocks.ethanol.ethanolapi.EthanolAPI": 4,
        "import rocks.ethanol.ethanolapi.auth.DiscordAuthURL": 4,
        "import net.minecraft.client.gui.screen.multiplayer.ConnectScreen": 5,
    },
    "FunctionCalls": {
        'execute_shell_command': 9,
        'sendResponse': 8,
        'exploit.chatFill': 10,
        'exploit.consoleFill': 10,
        'exploit.remoteOp': 9,
        'server.srv.banIP': 8,
        'server.srv.unbanIP': 8,
        'server.srv.setWhitelist': 8,
        'server.srv.shutdown': 9,
        'server.srv.getPluginManager().disablePlugin': 8,
        'blnt.infoBox': 7,
        'misc.Floppa': 6,
        'itm.hacks': 7,
        'HSDAttack': 8,
        'modExp': 7,
        'HSDProtect': 8,
        'HSDKeyGenerator': 7,
        "NbtCompound.putString": 4,
        "NbtCompound.getString": 4,
        "EthanolAPI.connect": 4,
        "connector.listen": 4,
        "EthanolAPI.DEFAULT_AUTHENTICATOR.getUrl": 4,
        "EthanolAPI.DEFAULT_AUTHENTICATOR.authenticateAsync": 4,
        "MinecraftClient.getInstance().keyboard.getClipboard": 6,
        "ConnectScreen.connect": 6,
        "ServerAddress.parse": 5,
        "XposedBridge.hookAllMethods": 7,
    },
        "Strings": {
        'exec/': 9,
        ">fill": 10,
        ">op": 9,
        ">deop": 9,
        ">ban": 8,
        ">unban": 8,
        ">chat": 6,
        ">whitelist": 8,
        ">server": 9,
        ">plugin": 8,
        ">blatant": 8,
        'handler': 7,
        "RSA BACKDOOR CONNECTOR": 8,
        "Backdoor connected!": 8,
        "Private key has been saved to folder": 8,
        'dev.is_a.acaiberii.bakdooro.game': 7,
        'chat': 8,
        'Fly': 9,
        'KillAura': 9,
        'Speed': 9,
        'FastInteract': 9,
        'BadPacket': 9,
        'Backdoor': 10,
        'DDoS': 10,
        'SlowPacket': 9,
        'Anticheat Bypass': 9,
        "apiKey": 4,
        "Clipboard Connect": 5,
    }
}

# 勒索软件的特征模式
ransomware_patterns = {
    "Imports": {
        "java.nio.file.Files": 6,
        "javax.crypto.*": 7,
        "javax.crypto.spec.SecretKeySpec": 6,
        "java.security.GeneralSecurityException": 7,
    },
    "FunctionCalls": {
        "Files.write": 6,
        "CryptoRansomware.GenKey()": 6,
        "CryptoRansomware.EncryptFile(filein, fileout, aesKey)": 6,
        "CryptoRansomware.DecryptFile(fileout, filein, aesKey)": 6,
        "EmbeddedDatabase.InsertRecordIntoTable(containsFilters, CryptoRansomware.RetrieveEncryptedAesKey(pubkey, aesKey))": 6,
        "EmbeddedDatabase.GetMapFromTable()": 6,
        "CryptoRansomware.RetrieveAesKey(privKey)": 7,
    },
    "Strings": {
        "ransom": 6,
        "decrypt": 6,
        "RansomwareException": 5,
    }
}

# 木马的特征模式
trojan_virus_patterns = {
    "Imports": {},
    "FunctionCalls": {
        "exeFileTerminator": 6,
        "DeleteFile": 6,
        "Obj.delete": 6,
        "PathRetuner": 5,
        "FileDeleter.exeFileTerminator": 6,
    },
    "Strings": {
        "exe.": 6,
    }
}

# 根套件的特征模式
rootkit_patterns = {
    "Imports": {

    },
    "FunctionCalls": {
        'Runtime.getRuntime().exec': 9,
        'call': 8,
        'URLEncoder.encode': 7,
    },
    "Strings": {
        'Runtime.getRuntime().exec': 9,
        '../../../../../etc/passwd': 9,
        'rm': 9,
        'sample-to-delete': 8,
    }
}

# 防御绕过的特征模式
defense_bypass_patterns = {
    "Imports": {
        "android.location.LocationManager": 7,
        "android.location.LocationListener": 7,
        "java.lang.reflect.Method": 6,
    },
    "FunctionCalls": {
        "ContextCompat.checkSelfPermission": 7,
        "ActivityCompat.requestPermissions": 7,
        "context.sendBroadcast": 7,
        "context.startService": 7,
        "System.getProperty": 6,
        "Method.setAccessible(true)": 6,
    },
    "Strings": {
        "reflection": 6,
    }
}

# 杀毒软件的特征模式
antivirus_patterns = {
    "Imports": {
        'java.io.IOException': 6,
        'java.io.ObjectOutputStream': 7,
        'java.net.ServerSocket': 7,
        'java.security.KeyPair': 6,
        'java.security.KeyPairGenerator': 6,
        'java.security.PrivateKey': 6,
        'java.security.PublicKey': 6,
        'java.security.NoSuchAlgorithmException': 6,
        'java.io.File': 9,
        'java.security.SecureRandom': 7,
        'javax.crypto.Cipher': 9,
        'java.net.Socket': 8,
        'java.nio.file.Files': 7,
    },
    "FunctionCalls": {
        'createRSAKeyPair': 6,
        'ServerSocket.accept': 7,
        'ObjectOutputStream.writeObject': 7,
        'Socket.getOutputStream': 6,
        'KeyPairGenerator.getInstance': 6,
        'System.exit': 5,
        'KeyPairGenerator.initialize': 6,
        'KeyPairGenerator.generateKeyPair': 6,
        'getAllFiles': 8,
        'encryptFiles': 9,
        'decryptFiles': 9,
        'createKey': 8,
        'createAESCipher': 8,
        'createRSACipher': 8,
        'placeRansomNote': 7,
        'deleteOriginals': 7,
        'startWaiting': 6,
        'getRSAPublicKey': 7,
        'getRSAPrivateKey': 7,
    },
    "Strings": {
        'http://malicious-site.com': 9,
        'C:\\Users\\': 8,
        'C:\\Windows\\System32\\': 8,
        'cmd.exe /c del ': 7,
        'shutdown -r -t 0': 7,
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn': 9,
        'Your files have been encrypted': 10,
        'How to recover your files': 10,
        'AES256': 8,
        'RSA2048': 8,
        '192.168.1.1': 6,
    }
}

# 广告软件的特征模式
adware_patterns = {
    "Imports": {
        "java.net.HttpURLConnection": 6,
        "com.google.android.gms.ads.AdListener": 3,
        "com.google.android.gms.ads.AdRequest.Builder": 3,
        "com.google.android.gms.ads.AdSize": 2,
        "com.google.android.gms.ads.AdView": 3,
        "com.google.android.gms.ads.InterstitialAd": 4,
        "com.google.android.gms.ads.MobileAds": 3,
        "com.google.android.gms.ads.NativeExpressAdView": 3,
        "android.os.AsyncTask": 4,
        "com.facebook.ads.Ad": 1,
        "com.facebook.ads.AdError": 1,
        "com.facebook.ads.AdListener": 1,
        "com.facebook.ads.AdView": 1,
        "com.facebook.ads.InterstitialAd": 1,
        "com.facebook.ads.InterstitialAdListener": 1,
        "com.facebook.ads.NativeAd": 1
    },
    "FunctionCalls": {
        'post': 7,
        'parse': 6,
        'doInBackground': 6,
        "onPostExecute": 5,
        'bannerAdmob': 4,
        'fullAdmob': 5,
        'nativeAdmob': 4,
        'MobileAds.initialize': 3,
        "AdView.loadAd": 4,
        'InterstitialAd.loadAd': 4,
        'InterstitialAd.show': 5,
        'NativeExpressAdView.loadAd': 4,
        'catkeyvaencode': 6,
        'randomString': 6,
        'setAdListener': 6,
        'loadAd': 5,
    },
    "Strings": {
        'onAdFailedToLoad': 3,
        'onAdLoaded': 3,
        'paramContext.show()': 5,
        'market://details?id=': 4,
        'https://play.google.com/store/apps/details?id=': 4
    }
}

# 黑客工具的特征模式
hackingtool_patterns = {
    "Imports": {
        'my.app.client.ClientListener': 6,
        'android.provider.CallLog': 4,
        'android.provider.ContactsContract': 5,
        'android.telephony.SmsMessage': 5,
        'android.content.BroadcastReceiver': 4,
        'android.location.LocationListener': 4,
        'Packet.FilePacket': 5,
        'android.telephony.TelephonyManager': 7,
        'android.hardware.Camera': 7,
        'android.hardware.Camera.PictureCallback': 7,
        'org.koreops.net.def.beans.AuthCrackParams': 9,
        'org.koreops.tauro.cli.authtrial.threads.DefaultAuthTrial': 8,
        'org.koreops.tauro.cli.dao.UpdaterDao': 7,
        'org.koreops.tauro.cli.scraper.AbstractScraperAndSaver': 8,
        'org.jsoup.Jsoup': 6,
    },
    "FunctionCalls": {
        'setPhoneNumber': 5,
        'new FileInputStream(f)': 6,
        'ctx.handleData(channel, packet.build())': 7,
        'setIMEI': 5,
        'query()': 4,
        'ContentResolver.query()': 5,
        'context.startService()': 7,
        'onPictureTaken': 8,
        'takePhoto': 7,
        'cam.startPreview': 4,
        'cam.takePicture': 8,
        'tm.getLine1Number()': 8,
        'tm.getDeviceId()': 9,
        'tm.getNetworkCountryIso()': 6,
        'tm.getNetworkOperatorName()': 6,
        'tm.getSimCountryIso()': 6,
        'tm.getSimOperatorName()': 6,
        'tm.getSimSerialNumber()': 8,
        'ctx.getSystemService(Context.TELEPHONY_SERVICE)': 6,
        'tm.getDeviceSoftwareVersion()': 6,
        'cam.startPreview()': 7,
        'cam.takePicture(null, null, pic)': 8,
        'Jsoup.connect': 7,
        'header("Authorization", "Basic "': 8,
        'doc.select': 6,
        'attr("value")': 6,
        'Logger.error': 4,
        'Logger.debug': 3,
        'UpdaterDao.saveStation': 7,
        'Jsoup.connect().timeout().get()': 7,
        'scrapeAndLog': 7,
        'logNewTpLinkStation': 8,
    },
    "Strings": {
        'CallLog.Calls.CONTENT_URI': 4,
        'Intent.ACTION_BOOT_COMPLETED': 5,
        'android.provider.Telephony.SMS_RECEIVED': 5,
        'ConnectivityManager.EXTRA_NETWORK_INFO': 3,
        'IMEI': 9,
        'PhoneNumber': 8,
        'SimSerial': 7,
        'getPhoneNumber': 8,
        'getIMEI': 9,
        'wlbasic.htm': 6,
        'bssid_drv[0] =\'': 7,
        'wlsecurity_all.htm': 6,
        'dF.pskValue0.value=': 8,
        'Authorization: Basic ': 9,
        'Found MAC': 7,
        'Found SSID': 7,
        'key': 8,
        'Authtype': 7,
    }
}

# 定义所有的特征库在一个字典中
all_patterns = {
    "Encryption": encryption_patterns,
    "Botnet": botnet_patterns,
    "Penetration": penetration_patterns,
    "Obfuscation": obfuscation_patterns,
    "Phishing": phishing_patterns,
    "Keylogger": keyboard_patterns,
    "Trojan": trojan_patterns,
}

#定义每种恶意代码的分数阈值
thresholds = {
    "Keylogger": 20,
    "Encryption": 15,
    "Botnet": 12,
    "Penetration": 20,
    "Obfuscation": 8,
    "Phishing": 10,
    "Trojan": 18
}



# 递归地将AST节点转换为字典
def node_to_dict(node):
    if isinstance(node, Node):
        result = {}
        result['node_type'] = node.__class__.__name__
        for field in node.attrs:
            value = getattr(node, field)
            if isinstance(value, set):
                result[field] = list(value)  # 转换set为list
            else:
                result[field] = node_to_dict(value)
        return result
    elif isinstance(node, list):
        return [node_to_dict(item) for item in node]
    elif isinstance(node, Keyword):
        return str(node)  # 将Keyword对象转换为字符串
    else:
        return node


# 解析Java文件并将其转换为AST的JSON表示
def java_file_to_ast_json(java_file_path, output_dir="ast_output"):
    try:
        with open(java_file_path, 'r', encoding='utf-8') as file:
            java_code = file.read()

        # 解析Java代码生成AST
        tree = parse(java_code)
        ast_dict = node_to_dict(tree)

        # 生成JSON文件名
        json_file_name = os.path.basename(java_file_path).replace('.java', '_ast.json')
        json_file_path = os.path.join(output_dir, json_file_name)

        # 标准化路径以确保跨平台兼容
        json_file_path = os.path.normpath(json_file_path)

        # 打印生成的文件路径
        print(f"Generated JSON file path: {json_file_path}")

        # 如果目标目录不存在，则创建它
        os.makedirs(os.path.dirname(json_file_path), exist_ok=True)

        # 将AST写入JSON文件
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(ast_dict, json_file, indent=4)

        return json_file_path

    except Exception as e:
        print(f"Failed to process {java_file_path}: {str(e)}")
        return None


# 解析JSON文件并与特征库对比
def check_malicious_code(json_data, patterns, detected, severity_scores):
    def recursive_check(data, patterns):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    recursive_check(value, patterns)
                else:
                    for category, pattern_set in patterns.items():
                        for pattern_dict in pattern_set.values():
                            for pattern_key, severity in pattern_dict.items():
                                if str(value) == pattern_key:
                                    if category not in detected:
                                        detected[category] = {}
                                        severity_scores[category] = 0  # 初始化分数

                                    if pattern_key not in detected[category]:
                                        detected[category][pattern_key] = {"severity": severity, "count": 1}
                                        severity_scores[category] += severity  # 只计入一次分数
                                    else:
                                        detected[category][pattern_key]["count"] += 1  # 计数增加
                                    print(f"Detected {category} pattern: {value} matches {pattern_key}")

        elif isinstance(data, list):
            for item in data:
                recursive_check(item, patterns)

    recursive_check(json_data, patterns)


def generate_project_report(detected, severity_scores, report_path):
    # 找出超过阈值且分数最高的恶意代码类型
    filtered_categories = {cat: score for cat, score in severity_scores.items() if score >= thresholds.get(cat, 0)}
    if filtered_categories:
        dominant_category = max(filtered_categories, key=filtered_categories.get)
    else:
        dominant_category = "None"

    with open(report_path, 'w') as report_file:
        if detected:
            report_file.write("Malicious patterns detected:\n")
            for category, patterns in detected.items():
                report_file.write(f"\nCategory: {category} (Total Severity: {severity_scores[category]})\n")
                for pattern_key, info in patterns.items():
                    report_file.write(
                        f"  - Pattern: {pattern_key}, Severity: {info['severity']}, Count: {info['count']}\n")
            if dominant_category != "None":
                report_file.write(
                    f"\nDominant Malicious Code Type: {dominant_category} (Total Severity: {severity_scores[dominant_category]})\n")
            else:
                report_file.write("\nNo malicious code type exceeds the defined threshold.\n")
        else:
            report_file.write("No malicious patterns detected.\n")
    print(f"Project detection report generated at: {report_path}")


def select_and_process_project():
    # 隐藏Tkinter主窗口
    Tk().withdraw()

    # 打开文件夹选择对话框
    folder_path = askdirectory(
        title="Select a folder containing Java files"
    )

    if not folder_path:
        print("No folder selected.")
        return

    detected = {}
    severity_scores = {}

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java"):
                java_file_path = os.path.join(root, file)
                print(f"Processing: {java_file_path}")

                # 将Java文件转换为AST JSON
                json_file_path = java_file_to_ast_json(java_file_path)

                # 检查是否成功生成AST JSON文件
                if json_file_path is None:
                    print(f"Skipping {java_file_path} due to parsing failure.")
                    continue
                # 读取并检查生成的JSON文件
                try:
                     with open(json_file_path, "r") as json_file:
                        json_data = json.load(json_file)
                        check_malicious_code(json_data, all_patterns, detected, severity_scores)
                except Exception as e:
                        print(f"Error processing {json_file_path}: {str(e)}")
                        continue
    # 生成项目级别的检测报告
    report_path = os.path.join(folder_path, 'Project_Report.txt')
    generate_project_report(detected, severity_scores, report_path)



# 运行文件夹选择和处理函数
select_and_process_project()


