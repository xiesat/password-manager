# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.6.1] - 2026-10-15

### 修复
- `.gitignore` 的 `*.sk` 规则把跨语言夹具 `spec/fixtures/cross_language.sk` 也排除了，
  导致从 v0.6.0 的源码无法复现 Android core 校验。已加入例外并入库。
- CI 新增的 `kotlin-core` job 恢复全绿：在 ubuntu-latest 上编译 Android core 并跑完 **94 项**跨语言检查。

## [0.6.0] - 2026-10-15

### 新增（Android 客户端）
- **@@android/core@@**：纯 Kotlin/JVM 库，实现 v3 加密容器（AES-256-GCM）、schema 4 载荷、
  三方合并、混合逻辑时钟、局域网同步协议客户端、确定性密码生成器。
  与 Python 参考实现**逐字节一致**，共 **94 项跨语言检查**全部通过。
- **@@android/app@@**：Jetpack Compose 界面（解锁 / 列表 / 新增 / 扫码同步），
  仓库、ViewModel 与平台配置（网络权限、明文流量策略、禁止系统备份）。
- **@@android/verify-core.sh@@ / @@verify-core.ps1@@**：无需 Android SDK 即可校验 core ——
  从 Maven Central 拉取 Kotlin 编译器，编译并运行 @@spec/*.json@@ 黄金向量与跨语言加解密夹具。
- **CI 新增 @@kotlin-core@@ job**：在 ubuntu-latest 上自动跑上述校验，防止两端实现漂移。
- @@spec/fixtures/@@：Python 生成的跨语言加解密夹具（含非 ASCII 口令与 emoji）。
- @@spec/generator_vectors.json@@：密码生成器的跨语言向量。

### 修复（由跨语言测试发现）
- Kotlin 侧 GCM 密文布局：磁盘格式是 **tag || ciphertext**（Python 约定），
  而 JCE 的 @@doFinal@@ 返回 **ciphertext || tag**。若不转换，两端无法互解 —— 已在实现中显式转换并加测试。

## [0.5.0] - 2026-10-15

### 新增（局域网同步，可用）
- **@@sync_service.py@@**：局域网同步服务。桌面端作为主机监听 HTTP，展示配对二维码；
  也可作为客户端连接其他设备。端到端交换**整库密文**，链路上不出现明文。
- **认证与防重放**：二维码携带 256bit 配对令牌 → HKDF-SHA256 派生认证密钥 →
  HMAC-SHA256 签名（时间戳 + nonce + 方法 + 路径 + 请求体摘要），响应同样签名；
  时间窗与非重复 nonce 拒绝重放。
- **@@sync_dialog.py@@ + 「同步」菜单**：展示二维码/配对文本、一键复制、粘贴配对信息发起同步、
  同步日志与冲突提示。
- 合并仍由主机执行并原子写回；客户端校验响应签名后采用合并结果并落盘。
- 新增 @@spec/SYNC_PROTOCOL.md@@（协议规范）。
- 测试从 131 增至 **154**（新增协议/认证/端到端/控制器同步）。

### 说明
- 未使用 TLS：载荷本身已是 AES-256-GCM 密文，认证由配对令牌 + HMAC 提供，
  这样 Android 端无需处理证书体系。
- 未使用 mDNS：配对二维码直接携带主机地址与端口，少一个依赖、更稳。
- 同步窗口关闭即停止监听，不常驻后台。

## [0.4.0] - 2026-10-15

### 新增（多端同步基础，暂未接入 UI）
- **数据 schema v4**：记录新增稳定 @@id@@、混合逻辑时钟 @@hlc@@、@@deleted@@ 墓碑；
  载荷新增 @@vault_id@@ / @@rev@@ / @@tombstones@@ / @@sync_base@@。加密容器仍是 v3，兼容读取 v1–v3。
- **@@hlc.py@@**：混合逻辑时钟，定长编码、字典序即时间序，支持 @@observe()@@ 吸收对端时钟。
- **@@merge.py@@**：三方合并引擎 —— 两端离线同时修改后合并，**任何一端的编辑都不会被静默丢弃**：
  不同记录自动合并；同记录冲突时两个版本都保留（确定性 @@uuid5@@ 副本 ID，保证两端收敛）；
  删除 vs 编辑时保留存活版本；历史按条目并集合并。
- **@@spec/VAULT_FORMAT.md@@ + @@spec/merge_vectors.json@@**：跨平台格式与合并规范，含黄金测试向量，
  供后续 Android 端逐字节对齐。
- 测试从 75 增至 **131**，新增 HLC / 合并 / 双端同步模拟 / 黄金向量四组测试。
- mypy 覆盖扩展到 9 个核心模块。

### 变更
- 删除主体改为生成墓碑（保留并入同步），清空数据同理。

## [0.3.0] - 2026-10-15

### 新增
- 表格迁移到 **QTableView + QAbstractTableModel + QSortFilterProxyModel**：列排序、实时过滤、多选批量操作。
- 密码改为**显式加密存储**于库内；生成规则仅用于「重新生成」，不再依赖算法可复现。
- **CSV 导入 / 导出**（导出为明文，带风险确认与 UTF-8 BOM）。
- **深色主题**，支持浅色 / 深色 / 跟随系统（theme.py + 模板化 style.qss）。
- **中 / 英双语界面**（Qt tr() + resources/translations/app_en.qm），「视图 → 语言」切换（重启生效）。
- 空状态页（QStackedWidget）替代占位行；剪贴板清空倒计时；多选批量复制 / 删除。
- 表格新增「更新时间」列。
- mypy 纳入 CI（核心模块）；新增 tag 触发自动构建并发布 Release 的 workflow（含可选代码签名）。

### 变更
- 删除主体改为批量接口 `delete_subjects`；控制器改为基于行索引操作。
- 配置新增 `theme` 与 `language` 两项。

## [0.2.0] - 2026-10-15

### 安全（破坏性与加固）
- **文件格式升级到 v3**：改用 AES-256-GCM（AEAD），认证覆盖 nonce，
  修复旧版 CBC 中 IV 不受 HMAC 保护的问题。
- 移除硬编码外层密钥 `F_Y`；新建文件必须由用户设置密钥。
- PBKDF2 迭代次数提升到 600,000，并写入文件头，便于将来平滑升级。
- 密码生成改用 PBKDF2 密钥流 + 拒绝采样（v2），彻底移除对
  `random`（Mersenne Twister）的依赖与 `% 10**18` 的 60bit 熵上限。
- 仍可读取 v1/v2 旧文件；旧的无盐规则会在加载时升级为 v2 并提示重新保存。

### 修复
- 「另存为」现在会更新当前文件路径并清除未保存标记。
- 撤销栈增加上限（100），避免长时间使用导致内存膨胀。
- 备份时间戳改用正则解析，文件名含下划线时不再排序错误。
- 历史窗口补齐撤销/重做入口；切换主体时正确重建窗口。
- 保存改为原子写入（临时文件 + fsync + os.replace），避免写坏密码库。
- 关闭时的自动备份写入日志，不再依赖不可见的状态栏提示。

### 变更
- 配置从工作目录的 Base64 `last_file_config.ini` 迁移到
  `%APPDATA%\PasswordManager\config.json`。
- 新增滚动日志 `%APPDATA%\PasswordManager\logs\app.log`。
- 删除死代码 `utils.py` 与模型中的 `create_temp_backup`。

### 界面
- 引入集中式主题 `resources/style.qss`，移除全部内联配色；配色取自 App 图标。
- 密码列默认掩码，可在「视图 → 显示密码」切换。
- 新增常驻搜索框（实时过滤），替代原 Ctrl+F 弹窗。
- 标题栏只显示文件名，并带未保存标记 `*`；状态栏显示未保存提示。
- 新增「解锁密钥库」对话框（含强度、显示切换、二次确认）。
- 菜单补全为 文件/编辑/视图/帮助；「清空数据」移出工具栏。
