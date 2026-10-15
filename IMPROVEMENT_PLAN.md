# 密码管理器 · 完整改进计划

> 项目：`D:\System Default\Documents\code\python\password_manager - 副本`
> 技术栈：Python 3.10 – 3.14（本机 3.14.8） · PySide6 · PyCryptodome · PyInstaller
> 状态：**阶段 0–4 主体完成并通过验证**；剩余增强项见 §10
> 详细附件：[OPTIMIZATION_PLAN.md](OPTIMIZATION_PLAN.md)（后端/安全）、[UI_OPTIMIZATION_PLAN.md](UI_OPTIMIZATION_PLAN.md)（界面）

---

## 0. 执行摘要

| 维度 | 改进前 | 改进后 |
|---|---|---|
| 文件加密 | 双层 AES-CBC + HMAC，**IV 不被认证**，外层密钥硬编码 `F_Y` | 单层 **AES-256-GCM（AEAD）**，tag 覆盖 nonce，**无硬编码密钥** |
| 密钥派生 | PBKDF2-SHA256 **10 万次**、写死 | **60 万次**，迭代数**写入文件头**，可平滑升级 |
| 密码生成 | `random`(Mersenne Twister)，种子 `% 10**18` → **熵上限 ~60bit** | PBKDF2 密钥流 + 拒绝采样，**256bit**，算法带版本号 |
| 密码落盘 | 只存规则，旧无盐规则**每次加载都变** | 只存规则 + 算法版本；旧规则加载时**升级为 v2 并提示保存** |
| 文件写入 | 直接覆盖，崩溃即损坏 | **原子写入**（临时文件 + fsync + `os.replace`） |
| 配置 | 工作目录 `last_file_config.ini`（Base64 伪加密） | `%APPDATA%\PasswordManager\config.json` |
| 日志 | `print`（打包后全部丢失） | 滚动文件日志 `...\logs\app.log` |
| 死代码 | `utils.py` 整文件、`create_temp_backup` | 已删除 |
| 撤销栈 | 无上限、每次深拷贝 | 上限 **100** |
| 备份排序 | `split('_')`，文件名含下划线即出错 | 正则解析时间戳 |
| 另存为 | 不更新路径、不清除脏标记 | 修复并回归测试 |
| 历史撤销/重做 | 回调存在但**无 UI 入口** | 历史窗口工具栏按钮 |
| 界面 | 14 处内联配色、emoji 图标、**明文密码常显**、Ctrl+F 弹窗 | 集中式 QSS 主题、**默认掩码**、**实时搜索**、解锁对话框、脏标记 |
| 工程化 | 无依赖声明、无测试、无 CI、无文档 | `pyproject.toml`、**52 个测试**、ruff、GitHub Actions、完整开源文件 |

---

## 1. 目标与范围

**目标**：在保持向后兼容（旧 `.sk` 仍可打开）的前提下，把项目从"能跑的课程作业"
提升到"可公开发布的工程作品"。

**范围**：安全模型、数据格式、缺陷修复、界面与交互、工程化、开源发布。

**非目标**（本计划不做）：多用户/云同步、浏览器插件、移动端、第三方安全审计。

---

## 2. 统一路线图

| 阶段 | 内容 | 状态 | 主要产物 |
|---|---|---|---|
| **0 止血** | 敏感文件隔离、原子写入、配置迁移、日志、清理死代码 | ✅ 完成 | `.gitignore` `storage.py` `applog.py` |
| **1 安全加固** | AES-GCM v3、安全生成器、去硬编码密钥、KDF 参数入库、旧格式兼容 | ✅ 完成 | `encryption.py` `password_generator.py` `model.py` |
| **2 缺陷修复** | 另存为、撤销上限、备份时间戳、历史窗口、裸 except、密钥输入 | ✅ 完成 | `controller.py` `view.py` `model.py` |
| **3 工程化** | 依赖声明、测试、lint、CI、模块职责 | ✅ 主体完成 | `pyproject.toml` `tests/` `.github/workflows/ci.yml` |
| **UI 升级** | 主题、掩码、搜索、解锁流程、脏标记、菜单、对话框 | ✅ 主体完成 | `resources/style.qss` `view.py` `docs/*.png` |
| **4 开源发布** | README、LICENSE、CHANGELOG、SECURITY、CONTRIBUTING、模板 | ✅ 文件就绪 | 见 §8 |
| **后续** | QTableView 迁移、i18n、深色主题、CSV、签名与自动发布 | ⏳ 待办 | 见 §10 |

---

## 3. 阶段 0 · 止血（已完成）

1. **`.gitignore`**：排除 `build/ dist/ __pycache__/ *.sk *.tmp last_file_config.ini .password_manager_backups ` 等。
   已用 `git check-ignore` 验证 `dist/new_file.sk`、`last_file_config.ini`、`build/`、`dist/` 均被忽略。
2. **`storage.py`**：原子写入 + `%APPDATA%` 配置读写。
3. **`applog.py`**：滚动文件日志（512KB × 4），打包 `console=False` 时仍可排查。
4. **死代码清理**：删除 `utils.py`（零引用）、`model.create_temp_backup`、view 中重复的剪贴板定时器。
5. **敏感产物**：`dist/` 内的用户样例与备份目录已被 git 忽略（**文件本身保留，未删除**，避免误删真实数据）。
6. `git init -b main` 已执行，当前 24 个顶层条目待首次提交。

---

## 4. 阶段 1 · 安全加固（已完成）

### 4.1 加密升级到 v3
`encryption.py` 新增 `VaultCipher`：

```text
v3:<base64( "PMGR" | version(1) | iterations(4) | salt(16) | nonce(12) | tag(16) | ciphertext )>
```

- **AES-256-GCM**：`cipher.update(header + salt)`，认证覆盖 magic/版本/迭代数/盐/nonce/密文 → 修复旧版 IV 不受保护的问题。
- **PBKDF2-HMAC-SHA256，600,000 次**（OWASP 2023 基线），迭代数随密文保存。
- 删除硬编码外层密钥 `F_Y`；新建文件**必须**由用户设置密钥。

### 4.2 安全生成器 v2
`password_generator.py`：

- `generate_v2`：`PBKDF2` 派生密钥流 + **拒绝采样**（消除模偏差）+ 确定性洗牌。
- 盐由 `secrets` 生成；**去掉 `% 10**18`**，种子为完整 256bit。
- `generate_v1`：用**局部** `random.Random(seed)` 精确复刻旧算法（有测试对照全局 `random.seed` 版本），既兼容旧数据又消除全局 PRNG 污染。

### 4.3 规则版本化与兼容
规则格式扩展为 `len|lower|upper|digit|symbol|salt|v2`（旧 5/6 段视为 v1）：

- v1 有盐 → 原样复现；
- **v1 无盐**（本不可复现）→ 加载时升级为 v2、标记待保存并提示用户；
- **v2 及以前的所有旧文件都能打开**（v1/v2/v3 三种读取路径均有测试）。

---

## 5. 阶段 2 · 缺陷修复（已完成）

| 缺陷 | 修复 | 回归测试 |
|---|---|---|
| 「另存为」不更新路径/脏标记 | `_write_current(new_path=True)` 回填路径并 `mark_clean()` | `test_write_current_sets_path_and_clears_dirty` |
| 撤销栈无上限 | `UNDO_LIMIT = 100`，超出丢弃最旧 | `test_undo_stack_is_bounded` |
| 备份时间戳按 `_` 切分出错 | 正则 `_(\d{8}_\d{6})\.tmp$` | `test_backup_timestamp_handles_underscore_names` |
| 历史窗口撤销/重做无入口 | 历史窗口加工具栏按钮 + 回调 | UI 冒烟 |
| 切换主体时历史窗口不刷新 | 主体不同则重建窗口 | `test_history_window_populates_and_masks` |
| 控制器直接调 model 私有方法 | 新增 `reorder_subjects()` 公共方法 | `test_reorder_subjects` |
| 裸 `except: pass` 吞异常 | 改为捕获具体异常 + 日志 | ruff `B` 规则 |
| `print` 当日志 | 统一 `logging` | — |
| 标题暴露完整路径 | 只显示文件名，状态栏带脏标记 | `test_dirty_marker_in_title` |
| 密钥内联在工具栏、新建文件无需密钥 | 「解锁/设置密钥」对话框，新建需两次确认 | `test_dialogs_construct` |

---

## 6. UI 升级（已完成主体）

### 6.1 设计系统（取自 `resources/app_icon.png`）

| Token | 值 | 用途 |
|---|---|---|
| brand | `#2E5BE0` | 主按钮 / 选中 / 焦点 |
| navy | `#1B2A4A` | 标题 / 深色文字 |
| green | `#2BD98A` | 成功 / 强调 |
| danger | `#E5484D` | 删除 / 危险 |
| bg / surface / border | `#F5F7FB` / `#FFFFFF` / `#E2E8F0` | 背景 / 卡片 / 描边 |

字体 Microsoft YaHei UI，8px 栅格，控件 32px，圆角 8/10px。

### 6.2 效果图

![主界面](docs/ui-mockup-main.png)

![解锁与新增主体](docs/ui-mockup-dialogs.png)

### 6.3 已实现

- **`resources/style.qss`** 集中主题；删除全部内联 `setStyleSheet`；按钮用 `role="primary|danger|icon"`。
- **密码默认掩码** `••••••••`，真实值存 `Qt.UserRole`；「视图 → 显示密码」切换。
- **常驻搜索框**：`textChanged` 实时过滤行，替代原 Ctrl+F 弹窗（Ctrl+F 现在只聚焦）。
- **解锁对话框**：强度条、明文切换、新建时二次确认与丢失警示。
- **脏标记**：标题 `name *` + 状态栏 ● 提示；不再用 `setStyleSheet` 改状态栏颜色。
- **菜单补全**：文件/编辑/视图/帮助；危险操作「清空数据」移出工具栏。
- **历史窗口**：工具栏（显示/撤销/重做/复制/删除）+ 生成时间列。
- **窗口标题**去路径；快捷键补齐（Ctrl+N/O/Shift+S/L/Q、Ctrl+F）。

### 6.4 待办（见 §10）
表格仍为 `QTreeWidget`；未做深色主题与 i18n；空状态仍是占位行而非 `QStackedWidget`。

---

## 7. 阶段 3 · 工程化（主体完成）

- **依赖声明**：`requirements.txt`、`pyproject.toml`（含 ruff / pytest / mypy 配置，`requires-python = ">=3.10"`）。
- **测试**：`tests/` 共 **52** 个用例 —— 加密 11、生成器 12、模型 21、UI 冒烟 8。
- **静态检查**：`ruff check .` 全绿；`ruff format --check .` 19 个文件全部符合。
- **CI**：`.github/workflows/ci.yml` 在 windows-latest × Python 3.11–3.14 上跑 lint + format + 离屏测试。
- **模块职责**：`model` 不 import Qt；`view` 不含业务逻辑；`storage` / `applog` 独立。

---

## 8. 阶段 4 · 开源发布

### 已完成
- [x] [README.md](README.md)：功能、截图、安装、快捷键、安全模型、项目结构、路线图、英文摘要
- [x] [LICENSE](LICENSE)（MIT，含 PySide6 LGPL 提示）
- [x] [CHANGELOG.md](CHANGELOG.md)（Keep a Changelog 风格，`0.2.0`）
- [x] [SECURITY.md](SECURITY.md)（加密设计表 + 漏洞报告方式 + 已知限制）
- [x] [CONTRIBUTING.md](CONTRIBUTING.md)（含"改加密/格式必须补测试"约定）
- [x] `.github/PULL_REQUEST_TEMPLATE.md`、`.github/ISSUE_TEMPLATE/bug_report.yml`
- [x] PyInstaller spec：产物名改 ASCII `PasswordManager.exe`、图标移入 `resources/app_icon.ico`、排除测试依赖

### 待执行（需要你的账号/决定）
- [ ] 在 GitHub 创建空仓库，`git remote add origin ...`
- [ ] 首次提交与推送（见下面命令）
- [ ] 替换 README/CONTRIBUTING 中的 `OWNER/REPO`、LICENSE 中的 `<Your Name>`
- [ ] 打 tag `v0.2.0` 并用 spec 打包上传 Release（附 SHA256）
- [ ] （可选）代码签名证书

```bash
# 首次发布
git add -A
git commit -m "feat: v0.2.0 - AES-256-GCM v3 format, secure generator, UI overhaul"
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
git tag v0.2.0 && git push origin v0.2.0

# 打包
pip install pyinstaller
pyinstaller 密码管理器.spec
```

---

## 9. 验证与质量门禁

| 门禁 | 命令 | 结果 |
|---|---|---|
| 单元 + UI 测试 | `QT_QPA_PLATFORM=offscreen pytest -q` | **52 passed** |
| Lint | `ruff check .` | All checks passed |
| 格式 | `ruff format --check .` | 19 files formatted |
| 端到端启动 | 离屏创建窗口 → 写入库 → 断言 `v3:` | STARTUP_OK，`vault_prefix = v3:` |
| 忽略规则 | `git check-ignore -v` | 敏感文件全部 IGNORED |

关键回归用例：v3 往返/错密钥/密文篡改/**nonce 篡改**、v1 生成器对照、v2/v1 旧库可读、
无盐规则升级后可复现、另存为路径与脏标记、备份时间戳。

---

## 10. 剩余待办（按优先级）

| 优先级 | 事项 | 说明 |
|---|---|---|
| 高 | 处理工作区历史产物 | `dist/new_file.sk` 等已被 gitignore，但**是否删除由你决定**（可能是真实数据） |
| 高 | 人工验收 | 在真实 Windows 桌面跑一次完整流程（本项目测试为离屏） |
| 中 | 表格迁移 `QTableView + QAbstractTableModel + QSortFilterProxyModel` | 获得列排序、虚拟化、批量操作；替换占位行 hack |
| 中 | i18n（`tr()` + `.ts/.qm`）与英文界面 | 面向 GitHub 国际用户 |
| 中 | 深色主题 | 目前 QSS 为亮色单套 |
| 中 | 导入/导出 CSV/JSON | 便于迁移与外部备份 |
| 低 | mypy 严格化 | 配置已就绪，尚未纳入 CI |
| 低 | 空状态 `QStackedWidget`、剪贴板倒计时可视化 | 体验细节 |
| 低 | 自动发布 Action（tag → 构建 exe → Release） | 可选 |

---

## 11. 文件格式与兼容策略

```text
v3（当前写入）：v3: base64( PMGR|ver|iters|salt|nonce|tag|ct )   AES-256-GCM
v2（只读兼容）：v2: ct|iv|salt                                   双层 AES-CBC+HMAC
v1（只读兼容）：ct+iv（24 字符 iv）                              sha256(key) + AES-CBC
```

- 读取端按前缀/长度自动识别（`detect_format`）。
- 写入端**只用 v3**；打开旧文件不会原地改写，直到用户显式保存。
- 新增规则字段带 `v2` 后缀；解析器对 5/6/7 段均兼容。

---

## 12. 风险与回滚

| 风险 | 缓解 |
|---|---|
| 旧 v1/v2 文件读不出 | 保留独立解密路径 + 专门测试；不改动旧读取代码逻辑 |
| v1 无盐规则升级后密码变化 | 该类规则**本就不可复现**；升级后稳定，并在状态栏提示需重新保存 |
| v3 算法参数需要调高 | 迭代数已入库，可逐文件升级，无需全局破坏 |
| 误提交敏感文件 | `.gitignore` + `git check-ignore` 验证；提交前可 `git status` 复核 |
| 引入 PySide6/加密回归 | CI 在 3.11–3.14 多版本运行，含离屏 UI 冒烟 |

**回滚**：本仓库初始化后尚未提交，可直接删除 `.git` 放弃版本化；
代码层面 v3 写入为新增路径，如需退回可仅切换 `model.encrypt_data` 到旧实现（不建议）。

---

## 13. 本次变更清单

```text
新增：
  .gitignore  requirements.txt  pyproject.toml  README.md  LICENSE
  CHANGELOG.md  SECURITY.md  CONTRIBUTING.md  IMPROVEMENT_PLAN.md
  storage.py  applog.py  resources/style.qss  resources/app_icon.ico
  docs/ui-mockup-main.png  docs/ui-mockup-dialogs.png
  tests/{test_encryption,test_generator,test_model,test_ui_smoke}.py
  .github/workflows/ci.yml  .github/PULL_REQUEST_TEMPLATE.md
  .github/ISSUE_TEMPLATE/bug_report.yml

重写：
  main.py  controller.py  model.py  view.py  encryption.py  password_generator.py
  密码管理器.spec（name=PasswordManager，icon 改入 resources，新增 excludes）

删除：
  utils.py（死代码）

保留（供你决定）：
  build/  dist/  last_file_config.ini  last_file_config 等历史产物（已被 gitignore）
```

---

*本计划中的"已完成"均有对应代码与测试支撑；数字来自本机 Python 3.14.8（项目 .venv）的实际运行结果。*
