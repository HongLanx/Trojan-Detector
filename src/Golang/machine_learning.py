from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import numpy as np
from ssa_patterns_fin import encryption_patterns
from ssa_patterns_fin import penetration_patterns

# 示例文件特征
file_features = {
    "calls": [
        "net/http.init",
        "github.com/gobuffalo/packr.init",
        "io.init",
        "os/exec.init",
        "fmt.init",
        "os.init",
        "syscall.init",
        "os/user.init",
        "log.init",
        "os/user.Current",
        "log.Println",
        "HomeDir",
        "fmt.Println",
        "HomeDir",
        "HomeDir",
        "HomeDir",
        "DownloadFile",
        "DownloadFile",
        "DownloadFile",
        "os/exec.Command",
        "HideWindow",
        "SysProcAttr",
        "(*os/exec.Cmd).Start",
        "log.Println",
        "os/exec.Command",
        "HideWindow",
        "SysProcAttr",
        "(*os/exec.Cmd).Start",
        "log.Println",
        "os/exec.Command",
        "HideWindow",
        "SysProcAttr",
        "(*os/exec.Cmd).Start",
        "log.Println",
        "os.Create",
        "net/http.Get",
        "Body",
        "Body",
        "io.Copy",
        "println"
    ],
    "strings": [
        "\\\\Desktop\\\\e.exe",
        "\\\\Desktop\\\\o.exe",
        "\\\\Desktop\\\\s.exe",
        "http://127.0.0.1:...",
        "http://127.0.0.1:...",
        "http://127.0.0.1:...",
        "/C",
        "cmd",
        "/C",
        "cmd",
        "/C",
        "cmd",
        "Downloaded file"
    ]
}

# 合并调用和字符串特征，去重
all_features = list(set(list(penetration_patterns['calls'].keys()) + list(penetration_patterns['strings'].keys())))

# 生成输入数据和标签
X_train = []
y_train = []
for feature_set, feature_scores in penetration_patterns.items():
    for feature, score in feature_scores.items():
        vector = [1 if feature == fn else 0 for fn in all_features]
        X_train.append(vector)
        y_train.append(1 if score > 5 else 0)  # 恶意度大于5认为是恶意的

# 示例文件特征向量化
X_test = []
test_vector = [0] * len(all_features)
for feature_set, features in file_features.items():
    for feature in features:
        if feature in all_features:
            test_vector[all_features.index(feature)] = 1
X_test.append(test_vector)

# 转换为numpy数组
X_train = np.array(X_train)
y_train = np.array(y_train)
X_test = np.array(X_test)

# 假设 all_features 和训练/测试数据已正确设置
model = RandomForestClassifier(n_estimators=200)
model.fit(X_train, y_train)

# 输出特征重要性
feature_importances = model.feature_importances_
important_features = sorted(zip(all_features, feature_importances), key=lambda x: x[1], reverse=True)
print("特征重要性：")
for feature, importance in important_features:
    print(f"{feature}: {importance:.4f}")

# 对测试数据进行预测
predictions = model.predict(X_test)
prediction_probabilities = model.predict_proba(X_test)

# 输出预测结果和概率
print("预测结果：", "恶意" if predictions[0] == 1 else "非恶意")
print("预测概率：", prediction_probabilities[0][1])  # 输出被预测为恶意的概率