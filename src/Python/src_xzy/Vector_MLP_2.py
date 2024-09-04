import os
import ast
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# 1. 定义特征模式库
ransomware_patterns = {
    "win32api": 6, "win32file": 5, "Popen": 7, "Crypto.PublicKey.RSA": 6, "Crypto.Cipher.AES": 7,
    "Crypto.Random": 6, "winreg": 7, "win32event": 7, "winerror": 6, "hashlib": 6, "base64": 7,
    "ctypes": 8, "subprocess": 7, "uuid": 6, "win32file.GetDriveType": 6, "win32api.GetLogicalDriveStrings": 6,
    "is_optical_drive": 5, "AES.new": 7, "RSA.generate": 7, "RSA.importKey": 7, "self.pad": 6,
    "self.unpad": 6, "winreg.CreateKeyEx": 8, "winreg.SetValueEx": 8, "winreg.OpenKeyEx": 7,
    "winreg.DeleteValue": 7, "os.remove": 5, "webbrowser.open": 5, "pub.subscribe": 4,
    "Thread.start": 6, "Thread.stop": 6, "win32api.GetLastError": 6, "Popen.communicate": 6,
    "traceback.format_tb": 5, "hashlib.sha256": 6, "base64.b64encode": 7, "base64.b64decode": 7,
    "ctypes.cdll.LoadLibrary": 8, "re.findall": 5, "uuid.getnode": 6, "REGISTRY_LOCATION": 8,
    "STARTUP_REGISTRY_LOCATION": 8, "GUI_LABEL_TEXT_FLASHING_ENCRYPTED": 9, "BTC_BUTTON_URL": 8,
    "key.txt": 7, "C3C9BF85E96BC3489996280489C1EE24": 7, "vssadmin Delete Shadows /All /Quiet": 9,
    "encrypted_files.txt": 7, "Encryption test": 7, "Incorrect Decryption Key!": 8,
    "gui_title": 5, "YOUR FILES HAVE BEEN ENCRYPTED!": 9, "TIME REMAINING": 8,
    "WALLET ADDRESS:": 8, "BITCOIN FEE": 8, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 7,
    "AES Decryption Key": 8, "mutex_rr_windows": 8, "The file is corrupt and cannot be opened": 7,
    "VMware Registry Detected": 8, "VMwareService.exe & VMwareTray.exe process are running": 8,
    "VMware MAC Address Detected": 8, "exec(base64.b64decode(": 9, "Cracking Speed on RunTime": 7,
}


# 2. 提取特征的函数
def extract_features_from_code(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        code = file.read()

    # 使用AST解析Python代码
    tree = ast.parse(code)

    # 提取特征
    features = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                features.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            features.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    features.add(f"{node.func.value.id}.{node.func.attr}")
                elif isinstance(node.func.value, ast.Attribute):
                    features.add(f"{node.func.value.attr}.{node.func.attr}")
            elif isinstance(node.func, ast.Name):
                features.add(node.func.id)

    return features


# 3. 将特征向量化的函数
def vectorize_features(feature_patterns, sample):
    feature_vector = np.zeros(len(feature_patterns))
    pattern_list = list(feature_patterns.keys())

    for feature in sample:
        if feature in pattern_list:
            index = pattern_list.index(feature)
            feature_vector[index] = feature_patterns[feature]

    return feature_vector


# 4. 处理整个目录下的所有 .py 文件
def process_directory(directory):
    samples = []
    labels = []  # 所有标签都为1

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                features = extract_features_from_code(file_path)
                samples.append(features)
                labels.append(1)  # 全部标记为1（恶意代码）

    # 向量化所有样本
    X = np.array([vectorize_features(ransomware_patterns, sample) for sample in samples])
    y = np.array(labels)

    return X, y


# 5. 加载数据并进行训练和评估
directory = 'C:/Users/XXX19/Desktop/directory_to_scan'  # 指定你的目录路径
X, y = process_directory(directory)

# 数据分割为训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

# 训练随机森林模型
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 对测试集进行预测
y_pred = model.predict(X_test)

# 输出结果
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))
