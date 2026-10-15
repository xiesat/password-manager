# 密码管理器 Password Manager

本地优先的桌面密码管理器：**密码不以明文落盘**，由「主体名 + 盐 + 算法版本」确定性生成，
整个库以 **AES-256-GCM** 加密保存为单个 `.sk` 文件。

[![CI](https://github.com/xiesat/password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/xiesat/password-manager/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> ⚠️ 本项目为个人/学习向工具，**未经专业安全审计**。请勿将其作为关键凭据的唯一副本。

---

## 截图

![主界面](docs/ui-mockup-main.png)

![解锁与新增主体](docs/ui-mockup-dialogs.png)

---

## 特性

- **AES-256-GCM（AEAD）** 加密，认证覆盖 nonce，防篡改。
- **PBKDF2-HMAC-SHA256**，600,000 次迭代，参数随文件保存、可平滑升级。
- **整体加密存储**：密码随整个库一起被 AES-256-GCM 加密，同时保留生成规则用于「重新生成」。
- **可排序表格 + 实时搜索**（QTableView / QSortFilterProxyModel），多选批量复制与删除。
- **CSV 导入 / 导出**、**深色主题**（浅色 / 深色 / 跟随系统）、**中英双语界面**。
- 旧格式 **v1 / v2 兼容读取**，打开后自动升级为 v3。
- 撤销/重做、历史密码、拖拽排序、实时搜索。
- 密码列默认**掩码**，可一键显示；复制到剪贴板 30 秒后自动清空。
- **原子写入**（临时文件 + fsync + 替换），避免断电/崩溃写坏密码库。
- 自动备份到库文件同目录的 `.password_manager_backups/`，保留最近 10 份。
- 配置与日志写入 `%APPDATA%\PasswordManager\`，不使用工作目录。

---

## 安全模型

| 项目 | 说明 |
|---|---|
| 加密 | AES-256-GCM |
| 密钥派生 | PBKDF2-HMAC-SHA256，600,000 次，随机 16 字节盐 |
| 随机数 | `secrets` / `os.urandom` |
| 完整性 | GCM tag 覆盖 magic、版本、迭代数、盐、nonce、密文 |
| 密码生成 | PBKDF2 密钥流 + 拒绝采样（algorithm v2），无 60bit 熵上限 |
| 落盘内容 | `v3:<base64(header|salt|nonce|tag|ciphertext)>` |
| 密码形态 | 运行时在内存中为明文；落盘时随整个库一起被 AEAD 加密 |
| 明文落盘 | 无。单独的 `.sk` 文件泄露不直接暴露任何密码 |

**威胁模型边界**：本工具防御"密码库文件泄露"与"文件被篡改"。
它无法防御已被攻陷的操作系统、键盘记录器、内存取证或解锁期间的屏幕窥视。

---

## 安装与运行

需要 Python 3.10 – 3.14（PySide6 6.12 提供 `cp310-abi3` wheel，已在 **Python 3.14.8** 上验证）。

```bash
git clone https://github.com/xiesat/password-manager.git
cd REPO
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt
python main.py
```

### 打包为单文件 exe

```bash
pip install pyinstaller
pyinstaller 密码管理器.spec
# 产物：dist/PasswordManager.exe
```

> exe 未做代码签名，Windows SmartScreen 可能提示风险，请自行决定是否信任。

---

## 使用

1. **新建文件**：设置库文件位置 → 输入密钥两次（此密钥用于加密整个库，丢失不可恢复）。
2. **打开文件**：选择 `.sk` → 输入密钥解锁。若为 v1/v2 旧文件，将提示升级。
3. **新增主体**：填写名称与密码规则，立即生成密码。
4. 右键或工具栏可**生成新密码 / 复制 / 历史 / 删除**；`Ctrl+S` 保存。

### 快捷键

| 快捷键 | 动作 |
|---|---|
| `Ctrl+N` / `Ctrl+O` | 新建 / 打开 |
| `Ctrl+S` / `Ctrl+Shift+S` | 保存 / 另存为 |
| `Ctrl+Z` / `Ctrl+Y` | 撤销 / 重做 |
| `Ctrl+C` / `Delete` | 复制密码 / 删除选中 |
| `Ctrl+F` / `Ctrl+L` | 搜索 / 锁定 |
| `Ctrl+Q` | 退出 |

---

## 开发与测试

```bash
pip install pytest ruff
ruff check . && ruff format --check .
set QT_QPA_PLATFORM=offscreen && pytest -q    # Windows
```

测试覆盖：加解密往返与篡改检测、v1/v2 兼容、生成器确定性与 v1 回归、
规则解析、模型往返、撤销/排序、离屏 UI 冒烟。

---

## 项目结构

```
.
├─ main.py                  # 入口：日志、主题、启动
├─ controller.py            # 流程编排：文件、剪贴板、备份、自动加载
├─ model.py                 # 数据与加密编排（不依赖 Qt）
├─ view.py                  # PySide6 界面（不含业务逻辑）
├─ encryption.py            # VaultCipher(AES-256-GCM) + v1/v2 兼容解密
├─ password_generator.py    # v2 安全生成器（+ v1 兼容复现 + 强度评估）
├─ table_model.py           # QAbstractTableModel + 过滤/排序代理
├─ theme.py                 # 浅色/深色调色板与 QSS 生成
├─ io_exchange.py           # CSV 导入导出
├─ storage.py               # 原子写入、%APPDATA% 配置
├─ applog.py                # 滚动日志
├─ resources/style.qss      # 主题模板（占位符由 theme.py 替换）
├─ resources/translations/  # app_en.ts / app_en.qm（英文翻译）
├─ resources/app_icon.png
├─ tests/                   # pytest 测试
└─ docs/                    # 界面效果图与方案文档
```

---

## 路线图

- [x] 阶段 0：止血（原子写入、配置迁移、日志、清理死代码）
- [x] 阶段 1：安全加固（AES-GCM v3、安全生成器、去除硬编码密钥、兼容旧格式）
- [x] 阶段 2：修复已知缺陷（另存为、撤销上限、备份时间戳、历史窗口）
- [x] UI 升级：集中主题、掩码、实时搜索、解锁对话框、脏标记
- [x] 阶段 3：工程化（pyproject、pytest、ruff、CI）
- [x] 阶段 4：开源文件（README / LICENSE / CHANGELOG / SECURITY / CONTRIBUTING）
- [x] 阶段 5（v0.3.0）：QTableView/Model/Proxy、CSV 导入导出、深色主题、
      中英双语、空状态、剪贴板倒计时、mypy 与自动发布 workflow
- [ ] 后续：代码签名证书、编辑主体（改规则/重命名）、浏览器扩展

详见 [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md)。

---

## 许可证

本项目以 **MIT** 许可发布，见 [LICENSE](LICENSE)。

运行时依赖 [PySide6](https://www.qt.io/qt-for-python)（**LGPLv3**）与
[PyCryptodome](https://www.pycryptodome.org/)（Public Domain / BSD）。
以二进制形式分发时，请同时遵守 PySide6 的 LGPL 条款（附许可证文本，
并提供替换/重新链接 Qt 的方式）。若不想处理这些义务，可将本项目整体改用 **GPLv3**。

---

## English summary

A local-first desktop password manager (Python + PySide6). Secrets are **not stored
in plaintext**; passwords are derived deterministically from *(subject name + salt +
algorithm version)*, and the whole vault is encrypted with **AES-256-GCM**
(PBKDF2-HMAC-SHA256, 600k iterations, parameters stored in the file header).
Legacy v1/v2 vaults remain readable and are upgraded to v3 on open.
Atomic writes, rolling backups, clipboard auto-clear, and a masked password column
are included. Run tests with `QT_QPA_PLATFORM=offscreen pytest -q`.
Licensed MIT; PySide6 is LGPLv3.
