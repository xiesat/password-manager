# 密码管理器 项目优化方案 & GitHub 发布建议

> 审计对象：D:\System Default\Documents\code\python\password_manager - 副本
> 技术栈：Python 3.12 + PySide6 (Qt6) + PyCryptodome + PyInstaller
> 说明：本文档只给方案与建议，尚未改动任何源码。

---

## 一、项目现状（我已通读全部源码）

### 1.1 代码结构

| 文件 | 行数 | 职责 |
|---|---|---|
| `main.py` | 17 | 入口，创建 QApplication 与 Controller |
| `view.py` | 583 | PySide6 界面（主窗口、添加对话框、历史窗口） |
| `controller.py` | 562 | 事件处理、文件读写、剪贴板、自动备份/恢复 |
| `model.py` | 447 | 数据 CRUD、撤销/重做、加解密编排、备份、脏标记 |
| `encryption.py` | 74 | `AESCipher`（PBKDF2+HMAC+AES-CBC）与 `LegacyAESCipher` |
| `password_generator.py` | 159 | 由「主体名 + 盐」确定性生成密码 |
| `utils.py` | 33 | `ensure_data_dir` / `find_latest_backup` —— **全项目零引用（死代码）** |
| `密码管理器.spec` | 39 | PyInstaller 打包配置 |

### 1.2 核心数据流

```
用户输入「密钥」(user_key)
   │
   ▼
主数据 main_data = [{name, password, count, rule}]
   rule = "长度|小写|大写|数字|符号|盐"      ← 只存"规则"，不存明文密码
   │
   ├─ JSON(ensure_ascii=False)
   ├─ 内层加密：AES-CBC + PBKDF2(用户密钥, 随机盐) + HMAC-SHA256
   │      inner = base64(ct)|base64(iv)|base64(salt)
   ├─ 外层加密：AES-CBC + PBKDF2(硬编码 "F_Y", 随机盐)
   └─ 落盘： "v2:" + base64(ct)|base64(iv)|base64(salt)
```

- **打开文件时密码是现场"重新生成"的**：`load_data_from_decrypted_json()` 解析 rule 后调用 `PasswordGenerator` 重算密码。
- **文件格式 v1/v2 并存**，v1 用 `LegacyAESCipher`（sha256 直接当密钥、无盐无迭代）。
- **备份**：同目录 `.password_manager_backups/`，文件名 `原名_YYYYMMDD_HHMMSS.tmp`，关闭时自动备份，保留 10 个。
- **上次文件路径**：写在工作目录的 `last_file_config.ini`，Base64 编码。

### 1.3 仓库状态

- ❌ 不是 git 仓库（无 `.git`）
- ❌ 无 README / LICENSE / requirements / pyproject / 测试 / CI / .gitignore
- ⚠️ `build/`（47MB pkg）、`dist/`（47MB exe + `new_file.sk` + `last_file_config.ini` + `.password_manager_backups/`）都在源码目录内
- ⚠️ 根目录 `last_file_config.ini` 明文 Base64 泄漏了作者路径 `D:/System Default/Desktop/new_file.sk`
- ℹ️ 本机 Python 3.14.8；PySide6 6.12 的 `cp310-abi3` wheel 已验证可用于 3.14（旧字节码为 cpython-312）

---

## 二、问题清单（按优先级）

### 🔴 P0 — 安全（必须在上线前修）

**S1. 密码生成用非加密安全的 PRNG，且种子熵被截断到 ~60 bit**
- `password_generator.py:71-72,82`：`int(sha256(seed).hexdigest(),16) % 10**18` 后 `random.seed()`。
- 10^18 ≈ **2^59.8**，即无论密码多长，有效熵上限约 60 bit；`random` 是 Mersenne Twister，非 CSPRNG。
- 由于「文件只存规则、不存密码」，密码强度被这个算法硬锁死——这是整个项目最严重的问题。
- 我已实测：`forceSalt=None` 时两次生成结果不同（不可复现），显式盐时可复现。

**S2. 硬编码外层密钥，且新建文件等价于无密钥**
- `model.py:27` `file_verify_key = "F_Y"`；`model.py:186-189` 当 `user_key==0`（新建文件）时**内层也用 "F_Y"**。
- 源码一旦开源，"F_Y" 即公开：外层加密形同虚设；新建的空 `.sk` 任何人都能解开。外层应删除或降级为纯格式标识。

**S3. HMAC 未覆盖 IV（也未覆盖盐）**
- `encryption.py:37` `hmac.new(hmac_key, ciphertext, ...)` 只对密文做 MAC，解密端 `:49` 同。
- CBC 的 IV 被篡改不会被发现（首块明文被可控翻转）。应改 **AES-GCM**，或至少 MAC `iv || ciphertext`。

**S4. PBKDF2 迭代次数偏低且写死**
- `encryption.py:11` `PBKDF2_ITERATIONS = 100000`，低于 OWASP 对 PBKDF2-HMAC-SHA256 的 ≥600,000 建议。
- 迭代数没有写进文件头，未来想提高就会破坏旧文件解密。应存进文件格式。

**S5. 密码明文直接显示在主表格**
- `view.py:283` 列「密码」直接显示明文；没有掩码/一键显示，存在肩窥与截屏泄漏风险。

**S6. 敏感文件会被提交到 GitHub**
- `dist/new_file.sk`（真实用户样例数据）、`last_file_config.ini`（作者本机路径）、`.password_manager_backups/`、47MB exe。
- 必须在首次 `git init` 前用 `.gitignore` 排除，并删除工作区中的用户数据。

**S7. 无原子写入**
- `controller.py:131-140,158-169` 直接 `open(path,"w")` 覆盖原文件。断电/崩溃/磁盘满 → 密码库直接损坏。应先写临时文件再 `os.replace()`。

**S8. 配置用 Base64 "加密"路径并写在 CWD**
- Base64 不是加密；且若安装在 Program Files，CWD 可能不可写。应改为 `%APPDATA%/PasswordManager/config.json`，并去掉伪加密。

### 🟠 P1 — 正确性 / 可靠性 Bug

| 编号 | 位置 | 问题 |
|---|---|---|
| B1 | `controller.py:143-171` | 「另存为」不更新 `current_file_path`、不 `mark_clean()`；无路径时「保存」走导出也不回填路径 → 后续 Ctrl+S 行为错乱 |
| B2 | `model.py:347-366` | 撤销栈无上限，每次操作深拷贝整份数据 → 长会话内存持续增长 |
| B3 | `controller.py:400-415` | 备份时间戳用 `split('_')[-1]` 解析，文件名含下划线（如 `my_file`）时解析失败 → 排序/恢复选错备份 |
| B4 | `view.py:530-536` + `controller.py:322` | 历史窗口已打开时直接 `raise_()+return`，但控制器已重置 subject 与撤销栈 → 切换到其他条目仍显示旧主体 |
| B5 | `model.py:219-221` | v1 旧格式（5 段规则无盐）每次加载都会**重新随机生成密码**，历史窗口每次刷新结果都不同 → 旧文件不可复现、数据不稳定 |
| B6 | `model.py:169-176` / `controller.py:293-300` | 导入时对 5 段规则先算一次密码（丢弃）再 `_generate_password_and_rule` 重算一次，重复计算且逻辑混乱 |
| B7 | `controller.py:293-300` | 排序直接调用 `model._save_state()/_mark_dirty()` 私有方法（破坏封装），且按 name 匹配，重名会错配 |
| B8 | `view.py:130-132,571-576` | view 与 controller 各有一套 `clipboard_timer`/清空逻辑，view 那套基本是死代码 |
| B9 | `view.py:363-369` | `_on_key_text_changed` 与 placeholder 比较后再赋值，绕圈；`real_key_input` 与 `key_input.text()` 完全重复 |
| B10 | `controller.py:406-415,432-437,470-473` | 多处 `except: pass` / 裸 `except Exception: pass` 吞掉异常，故障静默 |
| B11 | `controller.py` 多处 `print()` | 打包后 `console=False`，所有 `print` 日志全部丢失，线上问题无法排查 |
| B12 | `model.py:426-447` `create_temp_backup`、`utils.py` 全部、`view.py` `start_clipboard_timer` | 死代码，从未被调用 |
| B13 | `controller.py:89` `initialize_empty_state` | 新建文件后只压入一份状态；但 `load_data_from_decrypted_json` 只 `mark_clean` 不压栈，撤销语义边界不清 |
| B14 | 全局 | 「导入数据」实际是"用密钥解开当前已打开的文件"，与"导出"命名和语义都不符 |

### 🟡 P2 — 架构 / 代码质量

- **职责过载**：`PasswordManagerModel` 单类 447 行，混合了数据 CRUD、撤销栈、加密编排、文件格式、备份、脏标记 6 种职责。
- **全局副作用**：`random.seed()` 污染全局 PRNG 状态。
- **重复实现**：`generateSecurePassword` 与 `regeneratePasswordFromSalt` 是同一套逻辑抄了两遍。
- **命名/风格混用**：`generateSecurePassword`（camelCase）与 `add_or_update_subject`（snake_case）并存；无类型注解规范；无 lint/format 配置。
- **无依赖声明、无版本号、无异常体系、无测试。**
- **无算法版本号**：只要改动生成逻辑，所有已保存账号的密码全会变化 → 用户登录失败。这是该「存规则不存密码」设计最大的长期风险。

### 🔵 P3 — 发布/工程化缺失

README、LICENSE、CHANGELOG、.gitignore、requirements/pyproject、测试、CI、Release、截图、Issue/PR 模板、SECURITY.md —— 全部缺失。

---

## 三、优化路线图（建议分 4 个阶段）

### 阶段 0 · 止血与建仓（0.5–1 天，先做，防止泄密）
1. `git init` 之前先写 `.gitignore`，排除 `build/ dist/ __pycache__/ *.pyc *.sk *.tmp .password_manager_backups/ last_file_config.ini`。
2. 从工作区删除 `dist/new_file.sk`、`dist/last_file_config.ini`、`dist/.password_manager_backups/`、根目录 `last_file_config.ini`（这些含用户数据/路径）。若要 Demo，改成用固定密钥生成的样例并写入仓库外。
3. 删除 `utils.py`、`model.create_temp_backup`、view 中重复的剪贴板逻辑。
4. 关键路径改成**原子写入**。
5. 表格「密码」列默认掩码，加"显示/隐藏"按钮；复制仍走剪贴板 30s 定时清空。
6. 把 `print` 全部换成 `logging`（写 `%APPDATA%/PasswordManager/logs/`），打包加 `console=False` 也能留痕。

### 阶段 1 · 安全加固（2–4 天，核心）
1. **换 AEAD**：用 AES-256-GCM 替换自研 CBC+HMAC，认证覆盖 IV/头部；文件格式升到 `v3:`，保留 v1/v2 只读兼容。
   - 或用 `cryptography` 库的 `AESGCM` + `Scrypt`/Argon2id。
2. **KDF 参数写入文件头**：迭代数/算法版本随文件走；PBKDF2 提到 600k，或换 Argon2id。
3. **删除硬编码外层密钥**；新建文件必须先设置用户密钥并做强度校验（长度 + zxcvbn 类评分），不允许 `user_key==0` 落盘。
4. **生成器改用 `secrets`/HKDF**，种子用完整 256 bit（去掉 `% 10**18`），引入 `generator_version` 字段。
5. **优先改为"直接加密存储密码"**：把 `{name, password, ...}` 整体加密；rule 只作为可选元数据。这样既不失安全性，又彻底消除"改算法→密码全变"的风险。若坚持确定性生成，也必须把主体名 + **主密钥**共同作为种子（类似 LessPass），并冻结算法版本。
6. 可选：集成 Windows DPAPI/`keyring` 记住最近一次密钥（仅本机、可选关闭）。

### 阶段 2 · 修 Bug 与健壮性（1–2 天）
- 逐条修复 B1–B14。
- 撤销栈限长（如 100，超出丢弃最旧）；备份文件名改用独立元数据或 ISO 时间戳。
- 统一异常层级与用户提示；区分"可恢复/致命"。

### 阶段 3 · 工程化（2–3 天）
1. 拆包，建议结构：
```
password_manager/
├─ main.py
├─ core/
│  ├─ crypto.py        # VaultCipher（AEAD + KDF + 版本化格式）
│  ├─ generator.py     # 生成算法 + algorithm_version
│  ├─ storage.py       # 原子读写、路径、配置(%APPDATA%)
│  ├─ backup.py        # 备份/恢复/清理
│  └─ vault.py         # 业务模型（CRUD/撤销/历史）
├─ ui/
│  ├─ main_window.py
│  ├─ dialogs.py
│  └─ history_window.py
├─ resources/
├─ tests/
├─ pyproject.toml
├─ README.md
└─ LICENSE
```
2. `pyproject.toml` + 依赖锁定：`PySide6==6.x`、`pycryptodome`（或 `cryptography`）；声明 `requires-python = ">=3.10"`（PySide6 6.12 的 abi3 wheel 已验证可在 3.14 安装）。
3. 测试（pytest）：加解密往返、v1/v2/v3 格式兼容、生成器确定性、备份命名/排序、撤销边界、原子写。
4. `ruff` + `mypy` + `pre-commit`。
5. GitHub Actions：Linux/Windows 上跑 `ruff + pytest`；打 tag 时用 PyInstaller 产出 Release 附件（产物名建议用 ASCII，如 `PasswordManager.exe`）。

### 阶段 4 · 开源发布（1 天）
见第四节清单。

---

## 四、GitHub 发布清单（照着做即可）

- [ ] `.gitignore`（见第五节模板）
- [ ] `README.md`（中英双语）：项目简介、**截图/GIF**、下载安装、使用步骤、**安全模型与威胁模型**、格式说明、FAQ、免责声明
- [ ] `LICENSE`：推荐 **MIT** 或 **GPL-3.0**。⚠️ PySide6 是 **LGPLv3**，用 PyInstaller 打包分发需遵守 LGPL（附许可证、允许替换/重链接）；若不打算处理，直接用 GPL-3.0 最省心。PyCryptodome 为 Public Domain/BSD，兼容。
- [ ] `requirements.txt` / `pyproject.toml`（固定版本）
- [ ] `CHANGELOG.md` + 语义化版本 `v0.1.0` + git tag + Release（附 exe + SHA256 校验值）
- [ ] `SECURITY.md`：说明"个人项目、未经专业审计、不要用于关键账号"，漏洞报告方式
- [ ] `CONTRIBUTING.md`、Issue/PR 模板、`.github/workflows/ci.yml`
- [ ] 项目描述/Topics：`python pyside6 password-manager encryption desktop`
- [ ] 首次提交前再次确认：`git status` 不含 `*.sk` / `*.tmp` / 配置文件 / 备份目录
- [ ] 说明 exe 未签名（Windows SmartScreen 会告警），或自费代码签名

---

## 五、可直接采用的模板

### 5.1 `.gitignore`
```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/

# PyInstaller
build/
dist/
*.spec.bak

# 应用产生的敏感文件（务必排除）
last_file_config.ini
*.sk
*.tmp
.password_manager_backups/
data/

# 编辑器 / 系统
.vscode/
.idea/
Thumbs.db
Desktop.ini
```

### 5.2 `requirements.txt`
```text
PySide6>=6.6,<6.9
pycryptodome>=3.20
```

### 5.3 原子写入（替换所有 `open(path,"w")`）
```python
import os, tempfile

def atomic_write_text(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)          # 原子替换
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
```

### 5.4 AEAD + 版本化格式（替代 `AESCipher` 的加密部分）
```python
import base64, os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

MAGIC        = b"PMGR"
FORMAT_VER   = 3
KDF_ITER     = 600_000          # 并写进文件头，便于将来升级
SALT_LEN     = 16
NONCE_LEN    = 12
TAG_LEN      = 16

class VaultCipher:
    def __init__(self, password: str):
        self._pw = password.encode("utf-8")

    def _key(self, salt: bytes, iterations: int) -> bytes:
        return PBKDF2(self._pw, salt, dkLen=32, count=iterations,
                      hmac_hash_module=SHA256)

    def encrypt(self, plaintext: str) -> str:
        salt  = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        header = MAGIC + bytes([FORMAT_VER]) + KDF_ITER.to_bytes(4, "big")
        cipher = AES.new(self._key(salt, KDF_ITER), AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        blob = header + salt + nonce + tag + ct
        return "v3:" + base64.b64encode(blob).decode("ascii")

    @classmethod
    def decrypt(cls, password: str, token: str) -> str:
        blob = base64.b64decode(token[3:])
        assert blob[:4] == MAGIC, "bad magic"
        version   = blob[4]
        iterations = int.from_bytes(blob[5:9], "big")
        salt  = blob[9:9 + SALT_LEN]
        nonce = blob[9 + SALT_LEN:9 + SALT_LEN + NONCE_LEN]
        tag   = blob[9 + SALT_LEN + NONCE_LEN:9 + SALT_LEN + NONCE_LEN + TAG_LEN]
        ct    = blob[9 + SALT_LEN + NONCE_LEN + TAG_LEN:]
        cipher = AES.new(PBKDF2(password.encode(), salt, dkLen=32,
                                count=iterations, hmac_hash_module=SHA256),
                         AES.MODE_GCM, nonce=nonce)
        cipher.update(blob[:9])
        return cipher.decrypt_and_verify(ct, tag).decode("utf-8")
```
> 说明：GCM 的 tag 已认证 `header+salt+nonce+ct`，彻底解决 S3；迭代数入库解决 S4；`v3:` 前缀保持格式自描述。

### 5.5 安全生成思路（若保留"确定性生成"）
```python
# 关键点：
# 1) 用 secrets / hashlib.pbkdf2_hmac / hkdf，绝不使用 random
# 2) 种子 = 主密钥 + 主体名 + 计数器（NOT 主体名 + 可读盐）
# 3) 完整 256bit 输出，不做 % 10**18 截断
# 4) 记录 algorithm_version，算法一旦冻结就不再改动
# 5) 字符映射用拒绝采样消除模偏差（不要直接用 b % len(alphabet)）
```

---

## 六、优先级建议（如果时间有限）

| 优先级 | 事项 | 收益 |
|---|---|---|
| 1 | .gitignore + 清理 dist/ 用户数据 | 防止隐私泄露（最紧急） |
| 2 | 原子写入 | 防止密码库损坏 |
| 3 | AES-GCM + 迭代数入库 + 删除硬编码密钥 | 真正的加密安全 |
| 4 | 改为加密存储密码本体 / 生成器加版本号 | 消除"改算法密码全变"的长期风险 |
| 5 | README + LICENSE + 测试 + CI | 达到可发布的开源标准 |
| 6 | 模块拆分 + ruff/mypy | 可维护性 |

---

*本方案基于对源码的静态审计，未实际运行 GUI（本机未安装 PySide6）。数值与结论均已在源码中定位，可逐条核对。*
