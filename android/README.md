# Android 客户端（P5）

桌面端（Windows / Python）与 Android 端通过**局域网**互通，不依赖云服务器。

## 目录结构

```
android/
├─ settings.gradle.kts / build.gradle.kts / gradle.properties
├─ core/                       # 纯 Kotlin/JVM 库：加密、格式、合并、协议、生成器
│  └─ src/main/kotlin/com/pmvault/core/{Crypto,Json,Hlc,Merge,VaultCipher,VaultModel,SyncProtocol,PasswordGenerator}.kt
│  └─ src/test/kotlin/com/pmvault/core/SpecVectors.kt   # 黄金向量校验入口
├─ app/                        # Android 应用（Jetpack Compose）
│  └─ src/main/java/com/pmvault/app/{MainActivity,VaultRepository,VaultViewModel}.kt
│  └─ src/main/java/com/pmvault/app/ui/VaultApp.kt
├─ verify-core.sh / verify-core.ps1   # 无需 Android SDK 即可校验 core
└─ README.md
```

## core 已与 Python 参考实现逐字节对齐

`core` 不依赖任何 Android API，可以直接在 JVM 上验证。它实现了：

- `Crypto`：SHA-256 / HMAC / **手写 PBKDF2-HMAC-SHA256** / **HKDF(RFC 5869)** / **UUIDv5(RFC 4122)**（手写是为了保证与 Python 对非 ASCII 口令的字节处理完全一致）
- `VaultCipher`：v3 加密容器（AES-256-GCM，注意磁盘布局是 **tag || ciphertext**，与 JCE 默认相反）
- `Merge`：三方合并、冲突保留、删除 vs 编辑复活、确定性 `uuid5` 副本 ID
- `Hlc`：混合逻辑时钟
- `SyncProtocol` / `SyncClient`：HKDF 派生认证密钥、HMAC 签名、响应签名校验、HTTP 同步
- `PasswordGenerator`：确定性生成器 v2（PBKDF2 密钥流 + 拒绝采样）
- `VaultModel`：schema 4 载荷读写（兼容旧中文键名）

### 运行校验（不需要 Android SDK）

```bash
bash android/verify-core.sh          # Linux / macOS / Git Bash
```

```powershell
powershell -ExecutionPolicy Bypass -File android\verify-core.ps1
```

脚本会从 Maven Central 下载 Kotlin 编译器（缓存到 `android/.kotlin-cache`），编译 `core` 并运行
`spec/merge_vectors.json`、`spec/generator_vectors.json` 以及跨语言加解密夹具，输出形如：

```
checks=94 failures=0
ALL KOTLIN CORE CHECKS PASSED
```

使用 Gradle 时也可以直接跑：

```bash
cd android && ./gradlew :core:specVectors
```

## 构建 APK

仓库已包含 **Gradle wrapper**，克隆后即可直接构建（需要 JDK 17+ 与 Android SDK）：

```bash
cd android
./gradlew :app:assembleDebug        # Windows: gradlew.bat :app:assembleDebug
```

产物：`android/app/build/outputs/apk/debug/app-debug.apk`

也可以用 Android Studio 直接打开 `android/` 目录运行。

> 工程路径含中文等非 ASCII 字符时，AGP 默认会拒绝构建；
> `gradle.properties` 里已设置 `android.overridePathCheck=true` 放行（现代 aapt2 能正确处理 UTF-8 路径）。

**不想自己编译**：每个 Release 都附带了 CI 构建好的
`PasswordManager-android-debug.apk`（debug 签名，可直接安装测试）。

## 使用流程

1. 桌面端：打开库 → 菜单「同步 → 局域网同步…」→ 显示配对二维码。
2. 手机端：安装 APK → 创建或打开同一个库（**相同密钥**）→ 顶部「同步」→ 扫描二维码。
3. 手机把本机密文发给桌面端，桌面端合并后回传，两端内容一致。

> 两端必须各自已持有**同一个库密钥**；协议不传输密钥。

## 平台相关说明

| 项目 | 处理 |
|---|---|
| 网络权限 | `INTERNET` + `ACCESS_NETWORK_STATE` |
| 扫描二维码 | `CAMERA`；通过 `zxing-android-embedded` 调起系统相机界面 |
| 明文流量 | 局域网同步使用 HTTP（载荷本身是 AES-256-GCM 密文），已按 `network_security_config.xml` 放行 |
| 备份 | `allowBackup=false` 且排除 cloud-backup / device-transfer，避免密码库被系统导出 |
| 主密钥 | 只保存在内存中，锁定/退出即清除 |

## 当前限制 / 后续

- Android 端**目前只做客户端**（桌面端是主机）；如需手机当主机，需要加一个 HTTP 服务（例如 NanoHTTPD）。
- 未实现生物识别解锁（可基于 `androidx.biometric` + Keystore 加一层）。
- `app` 模块的 Compose 界面需要在 Android Studio 里编译验证；`core` 已在本机 JVM 上通过全部黄金向量。
