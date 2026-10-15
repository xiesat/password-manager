# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.10.1] - 2026-10-15

### 修复
- **新增主体时自动生成的首个密码没有进历史**（桌面端与 Android 端都有）。
  原先只有"生成新密码"才会写历史，导致"第一次生成的那条"永远查不到。
  现在自动生成的首个密码也会写入历史（次数 0），历史里能同时看到首次与后续各次。
- 显式传入密码的场景（如 CSV 导入）**刻意不记历史**：那种情况下规则是随机造出来的、
  与密码并不对应，记进去会显示一条与真实密码不符的记录。

### 测试
- 新增回归测试：`test_add_subject_records_first_password_in_history`、
  `test_explicit_password_is_not_recorded_as_history`；Python 测试增至 **167** 项。

## [0.10.0] - 2026-10-15

### 性能（Android，P0/P1）
- **PBKDF2 提速 2.4×**：整次派生只创建并**复用一个 Mac 实例**，不再每轮迭代都新建 ——
  原先省掉的 iterations 次 provider 查找与对象分配才是主要开销。
  本机实测：20 万次 **96ms → 40ms**，60 万次 **291ms → 120ms**，
  已与平台原生实现（JCE 37ms / 112ms）基本持平。
- **保存不再重算密钥**：新增 `VaultKey`（密钥 + 盐 + 迭代数）并在会话内复用。
  手机端每次保存从"60 万次 PBKDF2"变成"一次 AES-GCM"：本机实测 **122ms → <1ms**。
  每次加密仍生成**新的随机 nonce**（GCM 下 nonce 绝不能重复）。
- **历史密码缓存**：同一条记录 + 库版本未变时直接复用上次结果，重开不再重算。
- 同步路径由 2 次 PBKDF2 降到 1 次（主机的盐不同，那一次不可避免）。

### 新增（跨语言测试）
- `spec/fixtures/reused_key.*`：Kotlin 用**复用盐**连续保存两次生成的夹具。
  Python 测试验证桌面端能打开，并断言"盐复用、nonce 每次不同"。
- Kotlin 跨语言检查增至 **128** 项；Python 测试增至 **165** 项。

### 说明
- **未改动任何文件格式**：盐与迭代数依旧写在文件头，桌面端照旧可读。
- 桌面端（Python）保存本身只要约 0.1–0.3 秒，本轮未改动其加密路径。

## [0.9.0] - 2026-10-15

### 新增（Android 体验）
- **全屏进度遮罩**：解锁、生成密码、保存、同步等 PBKDF2 耗时操作期间，显示"正在做什么"
  并吃掉点击避免重复触发，用户不会再误以为程序卡死。
- **历史密码逐条进度**：历史密码改为在**后台线程逐条还原**，显示进度条与
  "正在还原历史密码 3/10（每条要算 20 万次 PBKDF2）"；关闭详情页会取消未完成的计算。
- **App 图标与电脑端一致**：由 `resources/app_icon.png` 生成 5 档 mipmap、圆形图标
  与 adaptive icon；`android/tools/make_icons.py` 可随时重新生成。

### 修复
- **重新生成后界面不刷新**：`regenerate` 改为**替换成新的记录对象**，不再原地修改 Map。
  原地修改会让新旧 `records` 列表"结构相等"，Compose 判定无变化从而跳过重组。
- `refresh()` 同样改为拷贝成新的 Map 实例，双保险。

### 说明
- 本轮**没有**改 PBKDF2 的算法与迭代数（性能优化待确认后再做），
  只是把耗时的历史还原移出主线程，并给出可见进度。

## [0.8.0] - 2026-10-15

### 修复（同步体验）
- 桌面端：客户端同步改为**后台线程**执行，界面不再冻结；新增**进度条**与状态文字。
- 桌面端：同步结束弹出**明确的完成 / 失败提示**（含冲突条数），不再只写一行日志。
- 桌面端：主机侧收到同步请求时同样显示进度（新增 `sync_started` 信号）。
- 桌面端：同步进行中禁止关闭窗口，避免文件写入被打断。
- Android：同步 / 导入对话框**不再一点就关**，改为在对话框内显示进度与结果。
- 两端：同步完成后列表都会自动刷新。

### 新增（Android 功能补齐）
- **重新生成密码**：沿用原规则换新盐重算，次数 +1，旧密码写入历史（与桌面端语义一致）。
- **查看历史密码**：由规则**确定性还原**每条历史密码，可单独复制。
- 条目详情页：点一行打开，集中提供 复制 / 重新生成 / 历史密码 / 删除。
- 列表显示每条记录的生成次数。
- core 新增 `PasswordGenerator.parseRule()` / `regenerate()` / `defaultRule()`，兼容 5 / 6 / 7 段历史规则格式。
- 跨语言向量新增 11 条规则解析与 3 条历史还原；Kotlin 校验增至 **115** 项。

### 国际化
- 补齐 32 条新增文案的英文翻译（`app_en.ts` / `app_en.qm`，181 条全部完成）。

## [0.7.0] - 2026-10-15

### 新增（新设备"首次加入"）
- 桌面端同步服务新增**需认证的 @@GET /vault@@**：向新设备提供整库密文下载。
- Python @@SyncClient.fetch_vault()@@ 与 Kotlin @@SyncClient.fetchVault()@@ 均已实现。
- Android 新增 **@@"从桌面端导入"@@**：扫码 → 输入桌面端密钥 → 下载整库并保存，
  新手机无需任何手工拷贝即可完成加入；本机已有库时会二次确认（导入会覆盖）。
- 新增 @@spec/sync_vectors.json@@：HMAC 派生密钥与签名的**跨语言向量**（含空 body 的 GET）。
- 测试：Python **158** 通过；Kotlin/Android core 跨语言检查增至 **101** 项。

### 说明
- 为什么需要单独下载：空库走三方合并会被判成"对端删除了所有记录"，
  因此首次加入必须是**整份下载**，之后才进入合并流程。协议文档已补充该说明。

## [0.6.3] - 2026-10-15

### 修复
- CI / Release 的 Android job 不再使用上游已损坏的 `android-actions/setup-android@v3`
  （它会尝试安装已被移除的 `tools` 包而必然失败），改用 ubuntu-latest 镜像自带的 Android SDK。
- 构建前 `chmod +x gradlew`，避免 Windows 下提交的脚本在 Linux 上不可执行。

### 新增
- 发版现在**自动构建并附上 Android debug APK**，与 Windows exe 一起发布。

## [0.6.2] - 2026-10-15

### 修复（Android 现在真正可编译、可出包）
- `VaultApp.kt`：修正 `KeyboardOptions` 的包路径（`androidx.compose.foundation.text`），并为 `ListItem` 加 `@OptIn`。
- `app/build.gradle.kts`：补 `lifecycle-viewmodel-ktx`；`versionName` 升到 0.6.1。
- `core/build.gradle.kts`：去掉强制 JDK 17 toolchain，改为用当前 JDK 编译、产出 Java 17 字节码。
- `android/gradle.properties`：加入 `android.overridePathCheck=true`，允许工程路径含非 ASCII（中文目录）。
- `.gitignore`：加入 `.gradle/`、`local.properties`。

### 新增
- 提交 **Gradle wrapper**（`gradlew` / `gradlew.bat` / `gradle-wrapper.jar`），克隆后可直接构建。
- CI 新增 `android-app` job：构建 debug APK 并上传 artifact，保证 Android 端持续可编译。
- Release workflow 新增 `android` job：**每次发版自动构建并附上 Android debug APK** 与校验和。
- 首个可用 APK 已随 Release 提供：`PasswordManager-android-debug.apk`（minSdk 26 / target 35）。

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
