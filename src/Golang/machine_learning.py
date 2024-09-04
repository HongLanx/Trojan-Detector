import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import ssa_patterns_fin

# 构建数据集
data = {
    "feature": list(ssa_patterns_fin.penetration_patterns["calls"].keys()) + list(ssa_patterns_fin.penetration_patterns["strings"].keys()),
    "count": list(ssa_patterns_fin.penetration_patterns["calls"].values()) + list(ssa_patterns_fin.penetration_patterns["strings"].values())
}

# 预测新的文件特征
new_data = {
    "feature": [
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
        "println",
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

df = pd.DataFrame(data)

# 生成标签，这里我们简单地假设所有的特征都属于恶意特征（1代表恶意，0代表正常）
df['label'] = 1

# 分割数据集为训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(df['feature'], df['label'], test_size=0.3, random_state=42)

# 创建全特征列表
all_features = pd.concat([df['feature'], pd.Series(new_data['feature'])]).unique()
all_features_df = pd.get_dummies(pd.Series(all_features))

# 使用全特征列表重新编码我们的训练集和测试集
X_train_encoded = pd.get_dummies(X_train).reindex(columns=all_features_df.columns, fill_value=0)
X_test_encoded = pd.get_dummies(X_test).reindex(columns=all_features_df.columns, fill_value=0)

# 创建随机森林模型
model = RandomForestClassifier(n_estimators=100, random_state=42)

# 训练模型
model.fit(X_train_encoded, y_train)

new_df = pd.DataFrame(new_data)
new_df_encoded = pd.get_dummies(new_df['feature']).reindex(columns=all_features_df.columns, fill_value=0)

# 进行预测
predictions = model.predict(new_df_encoded)
print("预测结果：", predictions)
print(len(predictions))

# 打印分类报告
print(classification_report(y_test, model.predict(X_test_encoded)))
