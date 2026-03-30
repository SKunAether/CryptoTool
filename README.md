# CryptoTool - Burp Suite 加解密工具

一个与Burp Suite联动的加解密工具，支持常见加解密算法和哈希破解功能。

## 功能特点

- **对称加密**: AES, DES, 3DES, RC4 (支持ECB/CBC/CTR/GCM等模式)
- **非对称加密**: RSA, ECC
- **国密算法**: SM2, SM3, SM4
- **哈希算法**: MD5, SHA1, SHA256, SHA512, RIPEMD160
- **编码算法**: Base64, Base32, Base58, URL编码, HTML编码
- **哈希破解**: 内置714万条密码字典
- **在线API**: 支持调用在线加解密服务
- **批量处理**: 支持多行数据批量操作
- **历史记录**: 自动保存操作历史

## 安装

```bash
# 克隆项目
git clone https://github.com/your-username/CryptoTool.git
cd CryptoTool

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境 (Windows)
venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

## 使用

### 启动GUI工具
```bash
# Windows
start_gui.bat

# 或直接运行
python main.py
```

### 启动API服务器 (用于Burp Suite联动)
```bash
# Windows
start_api.bat

# 或直接运行
python plugins/burp_extension.py
```

## 界面说明

| 标签页 | 功能 |
|--------|------|
| 加解密 | AES/DES/RSA等加密解密 |
| 哈希 | 哈希计算 + 哈希破解 |
| 编码 | Base64/URL/HTML编码解码 |
| 批量处理 | 多行数据批量操作 |
| 在线API | 调用在线加解密服务 |
| 历史记录 | 查看操作历史 |

## 哈希破解

支持破解常见MD5/SHA1/SHA256等哈希值：

| 哈希 | 结果 |
|------|------|
| `21232f297a57a5a743894a0e4a801fc3` | admin |
| `5f4dcc3b5aa765d61d8327deb882cf99` | password |
| `e10adc3949ba59abbe56e057f20f883e` | 123456 |

字典文件位于 `config/password_dict.txt`，包含714万条常见密码。

## API接口

启动API服务器后，可通过HTTP请求调用：

### GET请求 - 获取API信息
```bash
curl http://127.0.0.1:8888
```

### POST请求 - 执行加密/解密
```bash
# Base64编码
curl -X POST http://127.0.0.1:8888 -H "Content-Type: application/json" -d '{"action":"encrypt","algorithm":"Base64","input":"Hello"}'

# Base64解码
curl -X POST http://127.0.0.1:8888 -H "Content-Type: application/json" -d '{"action":"decrypt","algorithm":"Base64","input":"SGVsbG8="}'

# MD5哈希
curl -X POST http://127.0.0.1:8888 -H "Content-Type: application/json" -d '{"action":"encrypt","algorithm":"MD5","input":"test"}'

# AES加密
curl -X POST http://127.0.0.1:8888 -H "Content-Type: application/json" -d '{"action":"encrypt","algorithm":"AES","input":"Hello","key":"1234567890123456","mode":"ECB"}'
```

### 支持的算法
| 算法 | 加密 | 解密 | 哈希 |
|------|------|------|------|
| AES | ✓ | ✓ | - |
| DES | ✓ | ✓ | - |
| 3DES | ✓ | ✓ | - |
| RC4 | ✓ | ✓ | - |
| RSA | ✓ | ✓ | - |
| Base64 | ✓ | ✓ | - |
| URL编码 | ✓ | ✓ | - |
| MD5 | - | - | ✓ |
| SHA256 | - | - | ✓ |

## 项目结构

```
CryptoTool/
├── main.py                 # 主入口
├── requirements.txt        # 依赖列表
├── start_gui.bat          # GUI启动脚本
├── start_api.bat          # API启动脚本
├── src/                   # 核心算法
│   ├── symmetric/         # 对称加密 (AES/DES/RC4)
│   ├── asymmetric/        # 非对称加密 (RSA/ECC)
│   ├── digest/            # 哈希算法 + 破解
│   ├── encoding/          # 编码算法
│   └── chinese/           # 国密算法 (SM2/SM3/SM4)
├── gui/                   # PyQt6图形界面
├── plugins/               # Burp Suite API服务
├── api/                   # 在线API客户端
├── utils/                 # 工具函数
├── config/                # 配置文件 + 字典
├── tests/                 # 测试文件
└── venv/                  # Python虚拟环境
```

## 依赖

- Python 3.9+
- PyQt6
- PyCryptodome
- cryptography
- gmssl (国密算法)
- requests

## 与Burp Suite联动

1. 启动API服务器: `start_api.bat`
2. API地址: `http://127.0.0.1:8888`
3. 在Burp Suite中配置扩展调用该API

## License

MIT

## 更新日志

### v1.0 (2026-03-30)
- 初始版本发布
- 支持AES/DES/3DES/RC4/RSA加密解密
- 支持MD5/SHA系列哈希
- 支持Base64/URL/HTML编码
- 国密算法SM2/SM3/SM4
- 哈希破解功能（714万字典）
- PyQt6图形界面
- REST API服务器
