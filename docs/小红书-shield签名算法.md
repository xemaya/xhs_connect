# 小红书 shield 签名算法还原（libxyass.so）

- 目标：小红书 App v9.36.2（未加固），`lib/arm64-v8a/libxyass.so`（597 KB，strip，无壳）
- 工具：Ghidra 12.1.4 静态反编译 + Unicorn 模拟执行（破解控制流平坦化/字符串解密）+ 自写 ELF/重定位解析
- 结论先行：**本库就是 OkHttp 拦截器 `XhsHttpInterceptor` 的 native 实现，产出两个请求头：`shield: XY<base64>` 和 `xy-platform-info: platform=android&build=<N>&deviceId=<id>`。`x-s`/`x-t`/`x-b3` 不是本库生成的。**
- shield 值结构（已用 Unicorn 端到端模拟 `FUN_14b3d0` 验证，见 §6）：

```
shield = "XY" + Base64标准字母表(
            hdr16 || RC4(key="std::abort();",
                          hdr24 || buildStr || deviceId || digest))
```

其中 `digest` 是对「规范化请求数据」的哈希/HMAC 结果（16 或 20 字节，取决于 mode），详见 §5。

---

## 1. 函数角色表

JNI 侧声明（`com/xingin/shield/http/Native.java`）：

```java
public static native void initializeNative();
public static native long  initialize(String token);
public static native Response intercept(Interceptor.Chain chain, long cPtr);
public static native void destroy(long cPtr);
```

RegisterNatives 在 `JNI_OnLoad`（Ghidra 地址 `0x13f484`）中完成，4 个方法名/签名由运行时解密确认（解密方法见 §3，结果经模拟执行验证）：

| Java 方法 | native 函数 | 签名 | 证据 |
|---|---|---|---|
| `initializeNative` | `FUN_0013faf8` | `()V` | JNI_OnLoad: name1 17B 解密 = `initializeNative`（fn `0x13d15c`，密文 va `0x167c0`） |
| `intercept` | `FUN_00145764` | `(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;` | name2 10B = `intercept`；sig2 49B 解密（fn `0x13c700`，va `0x161ac`） |
| `initialize` | `FUN_0014836c` | `(Ljava/lang/String;)V`→实际返回 jlong | name3 11B = `initialize`（fn `0x13b1c0`，va `0x15c70`） |
| `destroy` | `FUN_001487f4` | `(J)V` | name4 8B 内联密文 `0x6dde419c8ecbb40e` = `destroy`（fn `0x139c6c`） |

注意：任务书原先的猜测"intercept 是 FUN_0013faf8"**不成立**——`FUN_0013faf8`（1541 行）是 `initializeNative`（JNI 缓存初始化），`FUN_00145764` 才是 `intercept`。

关键辅助函数：

| 地址 | 角色 | 证据 |
|---|---|---|
| `FUN_0013f1bc` | `CallObjectMethodV` 变参包装 | 函数体调 `(*env)+0x118`（JNITable 索引 35 = CallObjectMethodV） |
| `FUN_00148f00` | `NewObjectV` 包装 | `(*env)+0xe8`（索引 29） |
| `FUN_0013f258` | `CallIntMethodV` 包装 | `(*env)+400`（索引 50） |
| `FUN_00148dc8` | `CallVoidMethodV` 包装 | `(*env)+0x1f0`（索引 62） |
| `FUN_0013f2f4` | `CallStaticVoidMethod` 包装（trace 日志） | 配合 `ContextHolder.writeLog(I)V`（静态方法 ID 存于 `g[0x13]`） |
| `FUN_00189da0` | 缓存 18 个 jclass 全局引用 + ContextHolder.writeLog 静态 mid | JNI_OnLoad 调用；类名全部解密确认（§3） |
| `FUN_001891dc` | **APK 签名校验（反篡改）**：getPackageInfo(自包名, 0x40).signatures，逐签名 `hashCode()` 与硬编码白名单比对，失败 `abort()` | 字符串解密：`getPackageManager`/`getPackageInfo`/`signatures`/`hashCode`；白名单为 ~18 个 int 常量（如 `-0x620f4d1f` 等，见 `0x1893xx-0x1895xx`） |
| `FUN_001467dc` | **shield 计算总装**：buffer→digest→`FUN_14b3d0`→`"XY"+…` | intercept 调用 |
| `FUN_00146a14` | digest 变体 A（mode>5）：MD5(canonical) → 自定义 keyed 混合 → 20B | MD5 IV 常量 @ va `0x15d40` |
| `FUN_00146d64` | digest 变体 B（mode≤5）：HMAC-MD5(key64, canonical) → 16B | 见 §5 |
| `FUN_0014b3d0` | **shield 拼装**：hdr24+build+deviceId+digest → RC4 → hdr16 → Base64 | Unicorn 模拟验证 ✓ |
| `FUN_00147050` | 406 重试逻辑：读取响应头 `xy-ter-str` 作为新密钥，写 SP，重算 shield 重放请求 | 详见 §7 |
| `FUN_00147548` | 密钥 setter：把 SP 中的字符串解析进 ctx（+0x30 子对象） | 控制流混淆，未逐指令还原（见 §9） |
| `FUN_00149634` | 密钥 getter：`FUN_00149634(*(cPtr+0x30), &modeKey, &aux)` 读出 `{int mode; byte key[64]}` | 调用点用法反推 |
| `FUN_00144c00` | 返回 build 号（long long），sprintf `"%lld"` 成字符串 | jumptable 混淆，来源不完全确定（见 §9） |
| `FUN_0011e7a4`/`FUN_0011e900` | `__cxa_guard_acquire/release`（一次性初始化锁） | 紧邻字符串 `__cxa_guard_acquire`（rodata va `0x1376a`） |
| `FUN_0011d9d8` | operator new | malloc 包装 |

JNI 表偏移证据（`(*env)+off`）：0x30 FindClass、0xa8 NewGlobalRef、0xb8 DeleteLocalRef、0x108 GetMethodID、0x388 GetStaticMethodID、0x480 GetStaticFieldID、0x488 GetStaticObjectField、0x4b0 GetStaticIntField、0x538 NewStringUTF、0x548/0x550 Get/ReleaseStringUTFChars、0x558 GetArrayLength、0x568 GetObjectArrayElement、0x580 NewByteArray、0x5c0/0x600 Get/ReleaseByteArrayElements、0x6b8 RegisterNatives、0x720 ExceptionCheck。

---

## 2. 全局上下文（cPtr）

`initialize(token)`（`FUN_0014836c`）返回一个 0x70 字节的 C++ 对象（即 Java 侧持有的 `cPtr`）：

| 偏移 | 内容 |
|---|---|
| +0x00 | std::string：token 原样拷贝 |
| +0x18 | std::string：`token + "_hmac"`（SharedPreferences 的键名） |
| +0x30 | 密钥子对象指针（`FUN_00147548` 写入；`FUN_00149634` 读出 `{int mode; byte key[64]}`） |
| +0x38 | `pthread_rwlock_t`（`pthread_rwlock_init` 初始化；读写密钥时加锁） |

`initialize` 流程（`FUN_0014836c`，证据：解密字符串 `_hmac`、`s` 及方法 ID 映射）：

```
ctx = new byte[0x70]
ctx.str0  = token
ctx.str18 = token + "_hmac"
app  = g[0x12]                       // Application 全局引用（见下）
sp   = app.getSharedPreferences("s", 0)            // DAT_00195fd8 = Context.getSharedPreferences(String,I)
val  = sp.getString(ctx.str18, "")                 // DAT_00195fe0 = SharedPreferences.getString
FUN_00147548(env, val, ctx)          // 解析/存入密钥子对象（FUN_00147548 内部混淆，见 §9）
pthread_rwlock_init(ctx+0x38)
return ctx
```

`g[0x12]`：`JNI_OnLoad` 里 `FindClass("android/app/ActivityThread")` → 静态方法 `currentApplication()Landroid/app/Application;` → 结果做 NewGlobalRef（三个字符串均为 rodata 明文：va `0x13f5b`/`0x12f88`/`0x131b8`）。

---

## 3. 混淆与字符串解密机制

### 3.1 指针/数据寻址混淆

全库所有跨函数指针、密文串地址都用同一手法隐藏：

- `.data.rel.ro` 中放一个槽位，由 `R_AARCH64_RELATIVE` 重定位填入 `load_bias + addend`（addend 有正有负，静态值为 0）；
- 代码里再 `slot_value ± K`（K 为 mov/movk 拼出的常数）得到有效地址。

Ghidra 因此显示成 `DAT_0019xxxx + 0xNNNNNNNN`。**还原公式（Ghidra 基址 0x100000）：**

```
effective_addr = 0x100000 + rela_addend(slot_vaddr) + K     （64 位回绕）
```

每个函数一个特征 K（如 JNI_OnLoad 用 `0x6e1e31a0`，initializeNative 用 `0x447b418c`）。本分析已按此公式解析全部 121 个解密块。

### 3.2 字符串解密函数族

至少 10 个控制流平坦化的解密函数：`0x13e6c0`、`0x13d15c`、`0x13a718`、`0x1391a4`、`0x139c6c`、`0x13b1c0`、`0x13c700`、`0x13dc28`、`0x13bc7c`、`0x144144`。调用模式统一：`buf = new char[n]; memcpy(buf, 密文, n); fn(buf, n);`（首次使用后由 `__cxa_guard` 保证只解密一次，明文缓存在全局槽）。

解密函数本身被「间接跳转 + 重定位加常数」重度混淆（`br xN`，目标 = 槽值 ± 常数），Ghidra 无法反编译（报 `Could not recover jumptable`）。**本分析不解算法本身，而是用 Unicorn 原样模拟执行**：映射 ELF 两个 LOAD 段 → 应用全部 RELATIVE 重定位 → 伪造栈/TLS（tpidr 金丝雀）→ 以 `(buf, len)` 直接调函数 → 读出明文。121 个加密串全部还原（112 自动 + 9 手工），代表样本：

| 密文位置 (va) | 解密 fn | 明文 |
|---|---|---|
| 0x167d8 | 0x13e6c0 | `com/xingin/shield/http/Native` |
| 0x161ac | 0x13c700 | `(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;` |
| inline `0x6dd35d59aec9b418` | 0x139c6c | `request` |
| inline `0x84a1b6` | 0x1391a4 | `xy-` |
| 0x16194 | 0x13d15c | `xy-platform-info` |
| 0x161f0 | 0x13d15c | `shield` |
| 0x161fc | 0x13e6c0 | `platform=android&build=%lld&deviceId=%s` |
| 0x15e00 | 0x13b1c0 | `xy-ter-str` |
| 0x16164 | 0x13dc28 | `_hmac` |
| 0x16170 | 0x13b1c0 | `closing the old response error` |

特征观察：内联 8 字节密文解出的短串（`request`/`proceed`/`headers`/`destroy` 等）每个字节与 `0x6dXX5X59…` 模式的密文关系疑似「逐字节 XOR 一个 0x6d/0x59 族密钥 + 位置扰动」；例如 `destroy` 的密文 `0e b4 cb 8e 9c 41 de 6d`（LE）与明文 `64 65 73 74 72 6f 79 00` 异或得 `6a d1 b8 fa ee 2e a7 6d`——非单字节 XOR，疑似带轮换/位置相关密钥。**精确解密算法未还原（不需要，模拟即可）；此点标注为不确定。**

### 3.3 反篡改

- `FUN_001891dc`：APK signatures 哈希白名单校验，失败 `abort()`（§1）。
- 大量函数（`FUN_00147548`、`FUN_00149634`、`FUN_00150010`、`FUN_0015a264`、`FUN_00144c00` 等）使用 jumptable 控制流混淆，Ghidra 反编译失败。
- digest 读取循环里有一段**死代码/诱饵**：把每个 4KB 数据块 hex 编码到 0x2000 缓冲后立即 free，结果从未使用（`FUN_00146a14`/`FUN_00146d64` 内，hex 表 `0123456789abcdef` @ va `0x15cc0`）。

---

## 4. initializeNative（FUN_0013faf8）

一次性 JNI 缓存（`writeLog(1/2)` 包裹开始/结束）：

1. 缓存 jmethodID 到全局槽（`DAT_00195fd8`…`DAT_00196770`），全部名称/签名已解密确认：

| 全局槽 | 类.方法 | 签名 |
|---|---|---|
| DAT_00195fd8 | Context.getSharedPreferences | `(String,I)Landroid/content/SharedPreferences;` |
| DAT_00195fe0 | SharedPreferences.getString | `(String,String)String` |
| DAT_00196040 | SharedPreferences.edit | `()Editor` |
| DAT_00196048 | Editor.putString | `(String,String)Editor` |
| DAT_00196050 | Editor.commit | `()Z` |
| DAT_001960d8 | Interceptor$Chain.request | `()Lokhttp3/Request;` |
| DAT_00196078 | Interceptor$Chain.proceed | `(Request)Response` |
| DAT_001960e0 | Request.url | `()Lokhttp3/HttpUrl;` |
| DAT_001960e8 | HttpUrl.encodedPath | `()String` |
| DAT_001960f0 | HttpUrl.encodedQuery | `()String` |
| DAT_001960f8 | Request.headers | `()Lokhttp3/Headers;` |
| DAT_001960a0 | Request.body | `()Lokhttp3/RequestBody;` |
| DAT_00196118 | Headers.size | `()I` |
| DAT_00196120 | Headers.name | `(I)String` |
| DAT_00196128 | Headers.value | `(I)String` |
| DAT_00196100 | okio.Buffer.<init> | `()V` |
| DAT_00196108 | okio.Buffer.writeString | `(String,Charset)Buffer` |
| DAT_00196110 | Charset.defaultCharset() 结果（全局引用） | — |
| DAT_00196138 | RequestBody.writeTo | `(Lokio/BufferedSink;)V` |
| DAT_00196090 | okio.Buffer.clone | `()Lokio/Buffer;` |
| DAT_00196098 | okio.Buffer.read | `([B)I` |
| DAT_00196140 | Request.newBuilder | `()Request$Builder` |
| DAT_00196058 | Request$Builder.header | `(String,String)Builder` |
| DAT_00196068 | Request$Builder.build | `()Request` |
| DAT_00196028 | Response.code | `()I` |
| DAT_00196030 | Response.header | `(String)String` |
| DAT_00196070 | Response(Body).close | `()V` |
| DAT_00196008 | Base64Helper.decode（static） | `(String)[B` |
| DAT_00196770 | Base64Helper.encodeToString（static） | `([B)String` |

2. 读取 `ContextHolder` 静态字段（类由 `FUN_00189da0` 缓存）：
   - `sDeviceId`（`Ljava/lang/String;`，GetStaticObjectField）→ 存 std::string `DAT_00195f78` + 全局 jstring `DAT_00196010`
   - `sAppId`（`I`，GetStaticIntField）→ 存 int `DAT_001960b0`
3. `build = FUN_00144c00()`（long long）→ `sprintf("%lld")` → std::string `DAT_00195f90` + 全局 jstring `DAT_00196778`
4. `snprintf("platform=android&build=%lld&deviceId=%s", build, deviceId)` → 全局 jstring `DAT_00196130`
5. 常量 jstring 全局引用：`DAT_00196038`="xy-ter-str"、`DAT_00196148`="xy-platform-info"、`DAT_00196060`="shield"
6. GetMethodID(`ContextHolder.isHttp()I`) → 经 `FUN_001491e8` 登记（该函数混淆，用途不确定）

---

## 5. intercept（FUN_00145764）完整流程

`writeLog(5)`（buildSourceStart）→ 组装规范化数据 → `writeLog(6)` → 读密钥 → `writeLog(7)`（calculateStart）→ 算 digest/shield → `writeLog(8)` → 写头 → proceed → 406 处理。

### 5.1 规范化数据（canonical）组装

```
request   = chain.request()                       // DAT_001960d8
url       = request.url()                         // DAT_001960e0
buf       = new okio.Buffer()                     // NewObject(Buffer,<init>)
charset   = cached Charset.defaultCharset         // DAT_00196110

buf.writeString(url.encodedPath(),  charset)      // DAT_001960e8
q = url.encodedQuery()                            // DAT_001960f0，可空
if (q != null) buf.writeString(q, charset)        // 注意：path 与 query 之间不插任何分隔符

// 收集请求中所有名字以 "xy-" 开头的 header（前 3 字节与 "xy-" 比较，
// 密文 inline 0x84a1b6 解密得 "xy-"）：
map<lower(name), value> m
for i in 0..headers.size()-1:                     // DAT_00196118/120/128
    n = headers.name(i); if (len(n)>3 && n[0..2]=="xy-") m[lower(n)] = headers.value(i)

// 按名字字典序（小写后）把「值」写入 buf；
// 并把 DAT_00196130（"platform=android&build=N&deviceId=D"）当作
// "xy-platform-info" 的值插入到排序位置：
fixed = "xy-platform-info"
inserted = false
for (name,value) in m:                            // std::map 迭代 = 升序
    if (!inserted && fixed < name) { buf.writeString(platformStr); inserted = true }
    buf.writeString(value)
if (!inserted) buf.writeString(platformStr)       // 全部小于 fixed 时追加在末尾
// 若 m 为空：只写 platformStr

body = request.body()                             // DAT_001960a0
if (body != null) body.writeTo(buf)               // DAT_00196138，原始请求体字节直接追加
```

### 5.2 密钥读取

```
pthread_rwlock_rdlock(cPtr+0x38)
FUN_00149634(*(cPtr+0x30), &mk, &aux)   // mk = {int mode; byte key[64]}
pthread_rwlock_unlock(cPtr+0x38)
```

### 5.3 digest 计算（FUN_001467dc → 两个变体）

输入：`mk.mode`、`mk.key[64]`、canonical buffer、`DAT_00195f90`(buildStr)、`DAT_001960b0`(sAppId)、`DAT_00195f78`(deviceId)。

**mode ≤ 5 → `FUN_00146d64`：**

```
ctx = FUN_0017f094()                    // malloc(0x138)，HMAC 上下文
ok  = FUN_0017f224(ctx, mode, key, 0x40) // 以 64 字节 key 初始化（HMAC-MD5）
if (ok == 0)  digest = (mode < 1) ? 00*16 : 01*16   // 失败兜底
else:
    clone = buf.clone(); ba = new byte[4096]
    while ((n = clone.read(ba)) != -1): FUN_0017feec(ctx, ba, n)   // Update
    FUN_0018001c(ctx, out, ...)                                     // Final
    digest = out[0..16]                     // 16 字节 → HMAC-MD5
```

证据：MD5 的 K 正弦表（`0xd76aa478`…）位于 va `0x94710` 数据段；`FUN_0017f094` 分配 0x138 上下文（≈ MD5_CTX×2 + key pad，典型 HMAC 结构）。**「HMAC-MD5」中的 HMAC 结构为推断（0x138 ctx + 64B key + 16B 输出），FUN_0017f224/17feec/18001c 本体混淆未逐指令确认；MD5 本身确凿。**

**mode > 5（实际 6/7）→ `FUN_00146a14`：**

```
FUN_0014eda8(md5)                        // MD5_Init：IV = 0123456789abcdeffedcba9876543210 @ va 0x15d40 ✓
while ((n = clone.read(ba)) != -1): FUN_0014ee94(md5, ba, n)   // MD5_Update（内部 += n*8 位计数 ✓）
FUN_0014f838(md5, &dg)                   // MD5_Final → 16B（后续按 20B 使用，高 4B 为 0）
if (mode == 6) FUN_00150010(key, 0x40, dg, 0x14, out)          // 自定义 keyed 混合 → 20B
if (mode == 7) { t = time(0); FUN_0015a264(key, 0x40, dg, 0x14, out, &t);
                 out[0x13] = t & 0xff }                        // FUN_0015a128 把时间戳低字节写进输出末字节
digest = out[0..20]                      // 20 字节
```

`FUN_00150010`/`FUN_0015a264` 内部混淆未完全还原（标注不确定；库中无 SHA-1/SHA-256/AES/ChaCha 常量，大概率仍是 MD5 族运算）。

### 5.4 shield 拼装（FUN_0014b3d0）——已模拟验证

```
FUN_14b3d0(sret=out, flag=1, buildStr, sAppId, mode, deviceIdStr, digest, digestLen)
  hdr24 = BE32(flag=1) || BE32(sAppId) || BE32(mode!=0 ? 2 : 1)
        || BE32(len(buildStr)) || BE32(len(deviceIdStr)) || BE32(digestLen)
  plain = hdr24 || buildStr || deviceIdStr || digest
  ct    = RC4(key="std::abort();", plain)              // 13 字节密钥，标准 KSA/PRGA
  hdr16 = {00, mode, 00, 04} || BE32(1) || BE32(len(plain)) || BE32(len(ct))
  out   = Base64标准字母表(hdr16 || ct)                 // 字母表 "A-Za-z0-9+/" @ va 0x16908
shield_header_value = "XY" || out
```

验证记录（Unicorn 直接调 `FUN_14b3d0`，输入 flag=1/build="9360002"/appId=1/mode=6/deviceId="devid-0123456789ab"/digest=01..10）：

- 输出 Base64 解码 → hdr16 = `00060004 00000001 00000041 00000041` ✓（mode=6、常数 1、长度 65/65）
- 用 `RC4("std::abort();")` 解密余下 65 字节 → hdr24 = `00000001 00000001 00000002 00000007 00000012 00000010` ✓（flag、appId、2、len 7/18/16）
- 载荷逐字节 == `buildStr || deviceId || digest` ✓

RC4 密钥字节取自 rodata va `0x13d9e`——恰好是字符串 `"std::abort();"`（混淆器复用现成串当密钥）；KSA 密钥下标在 `0..0xc` 回绕（13 字节）。

### 5.5 写请求头并 proceed

```
nb = request.newBuilder()                        // DAT_00196140
nb.header("shield", shieldValue)                 // DAT_00196058；DAT_00196060="shield"
nb.header("xy-platform-info", platformStr)       // DAT_00196148 / DAT_00196130
resp = chain.proceed(nb.build())                 // DAT_00196078 / DAT_00196068
resp = FUN_00147050(...)                         // 406 重试包装（§7）
return resp
```

---

## 6. shield 复现代码（Python，与模拟验证一致）

```python
import base64, struct

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

def shield(build: bytes, device_id: bytes, app_id: int, mode: int, digest: bytes) -> str:
    hdr24 = struct.pack('>6I', 1, app_id, 2 if mode != 0 else 1,
                        len(build), len(device_id), len(digest))
    plain = hdr24 + build + device_id + digest
    ct = rc4(b'std::abort();', plain)
    hdr16 = bytes([0, mode & 0xff, 0, 4]) + struct.pack('>3I', 1, len(plain), len(ct))
    return 'XY' + base64.b64encode(hdr16 + ct).decode()

# digest:
#   mode in 1..5 -> HMAC_MD5(key64, canonical)          (16B)
#   mode == 6    -> custom6(key64, MD5(canonical))      (20B, 内部未完全还原)
#   mode == 7    -> custom7(key64, MD5(canonical), t)   (20B, out[19] = t & 0xff)
# canonical = encodedPath + (encodedQuery 若存在) + 排序后的 xy-* header 值
#             (platformStr 插入在 "xy-platform-info" 排序位) + 原始 body 字节
```

---

## 7. 密钥来源与轮换（HMAC key provisioning）

1. App 本地：SharedPreferences 文件 `"s"`，键 = `token + "_hmac"`（`initialize` 时 `getString` 读出，`FUN_00147548` 解析为 `{mode, key[64]}` 存入 cPtr 子对象）。`FUN_00147548` 内部疑似经 `Base64Helper.decode`（initializeNative 专门缓存了它的 mid），**确切解析格式未还原（函数混淆）**。
2. 服务器轮换（`FUN_00147050`）：若 `chain.proceed` 返回 **HTTP 406（0x196）** 且响应头 **`xy-ter-str`** 存在：
   ```
   sp.edit().putString(token+"_hmac", resp.header("xy-ter-str")).commit()
   FUN_00147548(env, newKey, cPtr)          // 更新 ctx
   重新加锁读 {mode,key} → 重新 FUN_001467dc 计算新 shield
   builder.header("shield", newShield)      // 同一 builder 覆盖
   close 旧响应 → chain.proceed(builder.build())   // 重放请求
   ```
   （旁证：解密串 `"closing the old response error"` 是该路径上的日志。）

---

## 8. 加密原语识别结论

| 原语 | 结论 | 证据 |
|---|---|---|
| MD5 | **确认**（canonical 主哈希；mode 6/7 的第一级） | IV `0123456789abcdeffedcba9876543210` @ va `0x15d40`（`FUN_0014eda8` 拷贝进 ctx）；K 正弦表 `78 a4 6a d7…` @ va `0x94710`；Update 中 `+= n*8` 位计数 |
| HMAC-MD5 | 高置信（mode 1..5） | 0x138 上下文、64B key、16B 输出；函数体混淆，结构推断 |
| RC4 | **确认**（shield 外层加密），密钥 `"std::abort();"` | `FUN_14b3d0` 中 S 盒 0..255 初始化 + KSA（密钥下标 mod 13）+ PRGA XOR；Unicorn 模拟验证密钥正确 |
| Base64 | **确认**（标准字母表，含 `=` 填充） | 字母表 @ va `0x16908`，256 字节速查表 @ `0x16808`（= alphabet[b>>2]） |
| SHA-1 / SHA-256 / AES / ChaCha | **不存在** | 全库搜索 IV/K 表/S-box/"expand 32-byte k" 均无命中 |
| 自定义 keyed 混合（mode 6/7） | 存在但未完全还原 | `FUN_00150010`/`FUN_0015a264` 控制流混淆；输入 (key64, MD5, 20B)，mode 7 输出末字节 = time&0xff |

---

## 9. 不确定项（如实标注）

1. `FUN_00150010`（mode 6）与 `FUN_0015a264`（mode 7）内部算法未逐指令还原（jumptable 混淆）；只知输入输出形状。若要完全复现 mode 6/7，需对这两个函数做 Unicorn 模拟或动态调试。
2. `FUN_00147548`（密钥 setter，jumptable）与 `FUN_00149634`（getter）未逐指令还原；`{int mode; byte key[64]}` 结构是从 `FUN_146a14`/`FUN_146d64` 的消费方式反推的。getter 的第二输出（intercept 中 `local_f8`）用途未明（代码中未被实际使用）。
3. `FUN_00144c00`（build 号来源）未完全还原：它先调 `FUN_001451e8(env, Context)`，之后 jumptable；疑似 `PackageInfo.versionCode`/内部 build 常量。`platform=...&build=%lld` 中的值即其返回值。
4. 字符串解密函数的精确算法未还原（用模拟执行代替）；从密文/明文对看疑似「位置相关多字节 XOR」，仅供进一步研究。
5. `FUN_146d64` 中 `FUN_0017f224` 返回 0 的触发条件不明（兜底输出 16×00 或 16×01）。
6. `initializeNative` 末尾 `FUN_001491e8(Request.body_mid, ContextHolder.isHttp_mid)` 的用途不明。
7. `x-s`/`x-t`/`x-b3` 头不由本库产生；如需还原请分析 `libtiny.so`（8.6 MB，同目录）或 Java 层其它签名组件。

---

## 附录 A. 分析方法备忘

- 基址：Ghidra image base = `0x100000`，文中 va = Ghidra 地址 − 0x100000。
- 反编译产物：`~/re-targets/xhs-out/native-out/libxyass.so.funcs.c`（含全部追加反编译）。
- 字符串/指针还原脚本（Unicorn + RELATIVE 重定位解析）在分析期间建于 `/tmp`，完成后按惯例清理；核心公式见 §3.1。
- 全部 121 个加密串的（密文地址, 解密函数, 明文）三元组已随分析产出，关键条目见 §3.2 与 §4 表。
