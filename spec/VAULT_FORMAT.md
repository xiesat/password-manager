# 密码库格式与同步规范 (VAULT FORMAT v4)

> 本文件是三端（Windows 桌面 / Android）互操作的**唯一权威规范**。
> 任何平台实现都必须与 `spec/merge_vectors.json` 中的测试向量逐字节一致。

---

## 1. 两个版本号，不要混淆

| 层 | 版本 | 说明 |
|---|---|---|
| 加密容器 | `v3` | AES-256-GCM（见 `encryption.py`）。**v4 不改动加密层。** |
| 数据 schema | **4** | 载荷 JSON 内部结构（本文档）。由载荷里的 `schema` 字段标识。 |

也就是说：文件仍然是 `v3:<base64(...)>`，但解密后的 JSON 里 `schema == 4`。
旧版本（schema 1/2/3）仍然可以读取并自动迁移。

---

## 2. 加密容器（不变）

`@text
v3:<base64( "PMGR" | version(1) | iterations(4) | salt(16) | nonce(12) | tag(16) | ciphertext )>
`@

- 算法：AES-256-GCM；KDF：PBKDF2-HMAC-SHA256，迭代次数随文件保存。
- GCM tag 覆盖 magic / version / iterations / salt / nonce / ciphertext。
- 明文是 schema 4 的 JSON（UTF-8）。

---

## 3. 载荷 JSON（schema 4）

`@jsonc
{
  "schema": 4,
  "vault_id": "<32位hex，库的稳定标识，创建时生成，永不变更>",
  "device_id": "<本机8位hex设备标识，随库保存仅作参考>",
  "rev": 42,
  "mainData":   [ <记录>, ... ],
  "tombstones": [ <墓碑记录>, ... ],
  "historyData": { "<主体名>": [ [次数, 规则, 时间], ... ] },
  "sync_base": { "<记录id>": "<32位hex语义哈希>" }
}
`@

---

## 4. 记录结构

`@jsonc
{
  "id": "8f0c...",          // 必填。稳定 UUID(hex)。合并的唯一身份，改名不变
  "name": "Google",          // 主体名
  "password": "Ab3$kQ9m",    // 明文密码（外层已整体加密）
  "rule": "16|True|...|v2",  // 生成规则，仅用于"重新生成"
  "count": "3",              // 生成次数（展示用）
  "updated_at": "2026-10-15 21:04:11",
  "hlc": "0001750000000-0000-ab12cd34",  // 混合逻辑时钟，排序用
  "deleted": false           // true 表示墓碑
}
`@

### 4.1 语义哈希（semantic_hash）

只对"内容是否算变过"的字段做哈希，**忽略 `count` / `updated_at` / `hlc`**：

`@text
alive  : sha256( canonical_json({"name":..., "password":..., "rule":...}) )[:32]
tombstone: sha256( canonical_json({"deleted": true}) )[:32]
`@

其中 `canonical_json` = `json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",",":"))`。

> 墓碑不考虑 `name`：任何两个墓碑语义等价，避免"各自删除时名字不同"造成假冲突。

---

## 5. 混合逻辑时钟 (HLC)

`@text
<wall_ms:13>-<counter:04>-<device>
例：0001750000000-0000-ab12cd34
`@

- 定长零填充，因此**字符串字典序 == 时间序**。
- 同一毫秒内 `counter` 递增；溢出时 `wall` 进位。
- 收到对端记录时调用 `observe()`，保证本机之后产生的时间戳更大。
- 不要求两端时钟同步；HLC 只用于**确定性排序**，不用于"谁更新"的权威判断。

---

## 6. 三方合并规则

输入：`base`（`{记录id: 语义哈希}`）、`local`、`remote`（记录列表，含墓碑）。

| 条件 | 结果 |
|---|---|
| `local_hash == remote_hash` | 两边一致 → 取其一 |
| `local_hash == base_hash` | 只有远端改过 → 取远端 |
| `remote_hash == base_hash` | 只有本地改过 → 取本地 |
| 其他 | **冲突** → 见下 |

### 6.1 冲突处理

1. **删除 vs 编辑**（一方墓碑、一方存活）：**存活版本获胜**，记录一条 `delete_vs_edit` 冲突。
   宁可多一条记录，也不丢密码。
2. **双方都存活但内容不同**：按全序键 `(hlc, id, semantic_hash)` 选出 winner（获胜者保留原 `id`），
   落败版本生成**确定性副本**，记录 `both_modified` 冲突。
3. **双方都是墓碑**：取全序较大者，记录 `both_deleted`。

### 6.2 冲突副本 ID（必须两端一致）

`@text
copy_id = uuid5(NAMESPACE, "<vault_id>:<原id>:<loser.hlc>:<loser.语义哈希>")
NAMESPACE = 6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4051
`@

副本的 `name` 追加 `（冲突副本 <origin>）`，其中 `origin` 取自 HLC 的 device 段。

### 6.3 全序键为什么包含 semantic_hash

极端情况下两台设备可能拥有相同的 `device_id`，导致 `(hlc, id)` 完全相同。
把语义哈希并入全序键后，只要内容不同就一定可比较，**合并保持交换律**：
`merge(base, A, B)` 与 `merge(base, B, A)` 得到相同内容。

### 6.4 收敛要求

- 合并结果与列表顺序无关；用 `content_hash`（对 `(id, 语义哈希)` 排序后哈希）校验。
- 两端独立计算后 `content_hash` 必须相等。
- 合并后 `sync_base` 更新为结果中每条记录的语义哈希。
- **列表显示顺序不参与同步**（各端可自行排序/拖拽）。

---

## 7. 历史记录合并

`historyData` 按"条目并集"合并：同名主体下两个列表取并集并按时间倒序。
只增不删，保证不丢；代价是"删除某条历史"可能被对端重新带回。

---

## 8. 向后兼容

| 输入 schema | 读取 | 迁移动作 |
|---|---|---|
| 4 | ✅ | — |
| 1 / 2 / 3（中文键名） | ✅ | 为每条记录补 `id`、`hlc`、`schema`，规则损坏/无盐时修复，标记需重新保存 |
| 加密容器 v1 / v2 | ✅ 只读 | 解锁后按 v3 容器 + schema 4 重新保存 |

读取端永远只认 `schema` 字段；写入端永远写 schema 4。

---

## 9. 扩展到 3 台以上设备

当前三端为 2 台设备（桌面 + 安卓）。若将来增加到 N 台：
把 `sync_base` 的"单一基准哈希"升级为**逐记录版本向量** `{device: counter}`，
判定规则不变（可比较则取大者，不可比较即冲突）。列表与合并算法无需改动。

---

## 10. 测试向量

`spec/merge_vectors.json` 包含：

- `hash_vectors`：记录 → 规范化 JSON → 语义哈希，锁定哈希算法；
- `merge_cases`：base/local/remote → 期望的存活密码集合、冲突类型、副本 ID、`content_hash`。

跨平台实现（Kotlin/TypeScript）必须直接跑这份向量并全部通过，才算兼容。

---

*本规范由 Python 参考实现 `merge.py` / `hlc.py` 驱动；修改任一算法都必须同步更新本文件与测试向量。*
