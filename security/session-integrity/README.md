# 会话存储完整性：SID 签名覆盖范围验证与保护原型

## 结论先行

团队的判断 **不成立**。`SESSION_USE_SIGNER=True` 只对 **Cookie 里的 SID 字符串**
做 HMAC 签名，存储后端里的会话内容（msgpack/pickle 序列化后的 dict）没有任何
签名或完整性校验。能写存储的攻击者可以直接改内容、或把整条记录搬到别的 SID 下，
应用会照常反序列化并信任。

## 一、沿真实读写路径验证

### 保存路径（请求结束时）

1. `ServerSideSessionInterface.save_session()` 计算 `store_id = key_prefix + sid`
   （`src/flask_session/base.py:284`），随后调用后端的 `_upsert_session()`
   （`src/flask_session/base.py:305`）。
2. 以 Redis 后端为例，`_upsert_session` 只做 `serializer.dumps(dict(session))`
   然后 `client.set(...)`，写入值里不含任何 MAC（`src/flask_session/redis/redis.py`
   的 `_upsert_session`）。文件系统/SQL/Mongo 等后端结构相同，存的都是裸序列化数据。
3. SID 签名发生在 **写 Cookie** 这一步：`value = self._sign(app, session.sid)
   if self.use_signer else session.sid`（`src/flask_session/base.py:311`），
   签名用的是 itsdangerous `Signer(secret_key, salt="flask-session")`
   （`src/flask_session/base.py:200-203`）。

### 读取路径（请求进入时）

1. `open_session()` 从 Cookie 取 SID；开了签名则 `_unsign()` 验签，失败就发新 SID
   （`src/flask_session/base.py:332-346`）。这一步保护的是 **Cookie → SID** 的映射，
   防止攻击者自己编造 SID 后让服务端去查。
2. 拿到 SID 后 `_retrieve_session_data(store_id)` 直接从存储取字节并
   `serializer.loads()`（如 `src/flask_session/redis/redis.py` 的
   `_retrieve_session_data`），**没有任何针对存储内容的验签**。
3. 反序列化结果被原样装进 `session_class` 返回
   （`src/flask_session/base.py:353-354`）。

### 签名实际覆盖范围

| 对象 | 是否受 SID 签名保护 |
| --- | --- |
| 浏览器 Cookie 中的 SID（防伪造/篡改 SID） | 是 |
| 存储 key（`session:<sid>`，由 SID 派生） | 间接：攻击者无法通过伪造 Cookie 引用任意 key，但能直接改存储 |
| 存储 value（会话 dict 内容） | **否** |
| SID 与存储记录的绑定关系（防记录互换） | **否** |
| 应用归属 / 序列化格式版本 / 时效 | **否** |

## 二、本地假存储实证

`demo_01_signer_scope.py` 用内存假存储（`fake_storage.py`，接口与真实后端一致）
走完整 Flask 请求路径，实测：

1. 开启签名后，Cookie 是 `sid.timestamp.HMAC` 格式，但存储里只有裸 msgpack；
2. 直接改写存储记录（`role=user` → `role=admin`），应用读取成功；
3. 把 bob 的整条记录搬到 alice 的 storage key 下（alice 的签名 Cookie 不动），
   alice 读到 bob 的数据；
4. 只有伪造 **Cookie** 才会被 `BadSignature` 拦下。

```sh
.venv/bin/python security/session-integrity/demo_01_signer_scope.py
.venv/bin/python security/session-integrity/demo_02_protected.py
.venv/bin/python -m pytest security/session-integrity/test_integrity.py -q -o addopts=
```

## 三、会话内容完整性保护方案（本目录原型）

### 信封结构（`integrity.py`，整体再 msgpack 编码）

| 字段 | 作用 |
| --- | --- |
| `v` | 信封结构版本 |
| `sid` | 绑定会话标识，记录搬到别的 key 即验签上下文不符 |
| `ns` | 应用命名空间（如 `billing-app`），跨应用/多租户搬运被拒 |
| `fv` | 载荷格式版本，序列化格式演进后旧信封显式失效 |
| `iat` / `exp` | 签发时间与过期时间，存储层 TTL 的应用侧冗余校验 |
| `kid` | 签名密钥 id，支持轮换与退役 |
| `payload` | 原始序列化会话数据（仍是明文） |
| `mac` | HMAC-SHA256，对上述全部字段（长度前缀拼接，防拼接歧义） |

### 关键设计

- **验签顺序**：先解码信封 → 按 `kid` 取 key 验 HMAC（常量时间比较）→
  再比对 `sid/ns/fv` → 最后查 `exp`。上下文字段在 MAC 保护下，攻击者无法
  把信封改绑到别的 SID/命名空间。
- **密钥环 `KeyRing`**：一把在线签名 key + 多把只验签的旧 key。
  `rotate()` 平滑轮换；旧 key 标记 `retired=True` 后默认拒绝验签，
  迁移宽限期可显式传 `allow_retired=True`；退役的 key 不能再用于签名。
- **失败策略**（`protected_storage.py`）：任何 `IntegrityError` 都按
  "记录不存在"处理并记 warning，用户得到一个全新空会话，而不是 500，
  避免给攻击者提供判定信号。
- **集成点**：真实落地只需在各后端 `_upsert_session` 里 `seal()`、
  `_retrieve_session_data` 里 `open_envelope()`；迁移期可双读
  （先按信封验，失败再走旧格式并在下次写入时补签）。

测试覆盖（13 项全过）：载荷篡改、MAC 篡改、SID 间记录互换、跨命名空间、
格式版本不符、过期、无过期记录、未知 `kid`、退役 key 拒绝、宽限期验旧、
轮换后新记录用新 `kid` 且旧记录可验、退役 key 禁止签名。

## 四、威胁边界（不要过度承诺）

### 攻击者 A：能读/写存储，但拿不到应用密钥

- 能做：读取全部会话内容（**明文**，本方案不提供保密性）；删除记录
  （破坏可用性）；在 `exp` 窗口内把一条 **自己历史上合法获得的** 旧信封
  写回（重放）。若要严格防重放，需服务端为每个 SID 维护单调版本号/nonce，
  仅靠 HMAC + 过期无法完全阻止。
- 不能做：在不知道密钥的情况下篡改载荷、把记录互换到其他 SID、伪造其他
  命名空间或格式版本的信封而不被检测；任何改写都会让 HMAC 校验失败。

### 攻击者 B：能改应用密钥（SECRET_KEY / HMAC key）

- 完整性彻底失守：可以给任意 `sid/ns/fv` 组合签发合法信封，写入任意会话
  内容，也能伪造 Cookie 里的 SID 签名。
- 密钥轮换只能保护轮换 **之后** 的数据；泄露期间签发的记录无法靠轮换追溯
  撤销，需要配合 `kid` 黑名单（本原型的退役机制）让旧 `kid` 全部失效。
- 因此签名密钥必须与存储隔离保管（环境变量/KMS/专用密钥服务、最小权限、
  审计访问），"存储被攻破"不应自动等于"密钥被攻破"，否则本方案无意义。

## 五、完整性 ≠ 保密性

- HMAC 只保证 **完整性 + 来源真实性**：能发现被改过，但内容本身是明文，
  demo 第 1 步可直接看到 `payload`。
- 若会话内容本身敏感（如令牌、PII），需要在签名之外增加 **加密**：
  采用 AEAD（AES-GCM）或其封装（如 Fernet），把 `sid/ns/fv` 作为
  associated data 绑定，实现"加密且认证"；密钥管理同样适用本方案的
  密钥环与退役机制。
