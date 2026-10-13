# 小红书 Tiny 签名（libtiny.so）算法还原报告

- 目标：小红书 App v9.36.2（未加固），`lib/arm64-v8a/libtiny.so`（8.6 MB，strip）
- 工具：Ghidra 12.1.4 静态分析 + **Unicorn 2.1.4 自研模拟器全量模拟执行**（本库控制流/指针/字符串全部混淆，纯静态反编译不可读；本文所有运行时结论均来自模拟执行的实证）
- Ghidra 项目：`~/re-targets/xhs-out/ghidra_proj/XhsNative`，image base = **0x100000**（文中地址均为 Ghidra 地址）

## 0. 重要结论修正（x-s/x-t 问题）

任务书假设 libtiny 生成 `x-s/x-t`。**实测 libtiny 生成的是 `x-mini-mua` / `x-mini-s1` / `x-mini-sig` 三个头**（对主 API 路径 `/api/sns/...` 也一样）。全库（静态 + 运行时内存）中**不存在** `x-s`/`x-t`/`x-s-common` 字符串。`x-s/x-t` 应属于另一个组件（同目录的 `libxyass.so`，597 KB，本报告未深入）。任务书描述的 Java 链路本身无误，只是该链路产物是 x-mini-\* 系列签名头。

## 1. Java → native 调用链（与 jadx 对照核实）

```
okhttp 拦截器 n0c/p.java:86
  Map<String,String> mapH = idb.f.h(request.method(), url, bodyBytes);
idb/f.java:149  h():
  host = url.getHost(); path = url.getPath(); query = url.getQuery() or "";
  return (Map) j3.b(-1765467163, method, host, path, query, body);
com/xingin/tiny/internal/j3.java:125  b():
  return (T) t.a(i7, objArr);           // 直接透传
com/xingin/tiny/internal/t.java:85:
  public static native Object a(int i7, Object... objArr);   // → libtiny.so
```

- 返回 `Map<String,String>` 即签名头集合，拦截器逐条 `builderNewBuilder.header(k, v)` 加到请求上；**native 返回 null 是合法"未就绪"状态**（跳过不加头）。
- 签名前 SDK 必须先初始化（p.java `b()` 会 `wait()` 等待 "Tiny SDK init complete"）。

## 2. JNI 注册与 native 入口

### 2.1 JNI_OnLoad（Ghidra @ 0x2b045c）

全库被控制流混淆：函数被切成碎片，碎片间用**运行时间接跳转**连接，指针以"存储值 = 真实地址 + 常量偏移"编码（如 JNI_OnLoad 读 `[0x8cea30] = 0x3cd6768`，减 `0x3a25614` → 跳 `0x2b1154`；参数 `0x3cf0d3c` 减 `0x3a3fbd8` → `0x2b1164`）。Ghidra 因此报 "Could not recover jumptable"，字符串在静态数据段也是密文。

模拟执行 `JNI_OnLoad(vm, 0)` 实测流程：

1. `(*vm)->GetEnv(&env, JNI_VERSION_1_6)`（lr=0x2b1090 附近）
2. `env->FindClass("com/xingin/tiny/internal/t")`
3. `env->RegisterNatives(cls, methods, 1)`，**实测注册表**：

| name | signature | fnPtr (Ghidra) |
|---|---|---|
| `a` | `(I[Ljava/lang/Object;)Ljava/lang/Object;` | **0x283df0** |

4. 返回 `0x10006`（JNI_VERSION_1_6）

全库只注册这一个 native 方法；所有功能都通过 `t.a(opcode, Object[])` 的 **opcode 分发**实现。

### 2.2 native→Java 反向桥（关键架构）

libtiny 把大量逻辑（反射、设备信息采集、Context 操作）通过 JNI 回调 Java 完成：

- 桥函数 = Java 侧 `com.xingin.tiny.internal.t.b(int, Object[])`（jadx t.java:277，74 个 case 的 switch）
- 缓存位置：全局 `DAT_009575a8`（jclass of t）/ `DAT_009575b0`（jmethodID of `b(I[Ljava/lang/Object;)Ljava/lang/Object;`），另有装箱辅助 `DAT_00958138/0x958148` 等
- 调用辅助：变参 trampoline `FUN_0041aac0`（构造 aarch64 va_list 后调 `CallStaticObjectMethodV`）
- 桥缓存由 **opcode -907571125** 初始化（即 `j3.a(long)`，App 在 `idb.f.g()` 里 loadLibrary 后立刻调用 `t.a(-907571125, Long.valueOf(uptimeMillis))`）。该 opcode 实测缓存了：`java/lang/Object`(toString/hashCode/clone/equals)、`Integer/Long/Float/Boolean/Double`(valueOf/xValue)、`t.b`、`Context`(getPackageManager/getContentResolver/...) 等约 30 个全局 JNI 引用（写地址 0x957500–0x958148，模拟器写监视实证）。
- GetEnv/Attach 包装函数 `FUN_0068e038`（先 `GetEnv`，失败则 `AttachCurrentThread`）。

### 2.3 初始化时序（App 侧，jadx 实证）

1. `tc.b.a(context, "tiny")` 加载 libtiny.so → `JNI_OnLoad`
2. `j3.a(SystemClock.uptimeMillis())` → `t.a(-907571125, Long)`：**初始化 Java 桥**
3. `hjc/n1.java:495` `j3.a(idb.c)` → `t.a(1012919688, 17 个配置参数)`：**SDK 配置**（见 §4.2）；native 侧会采集 PackageInfo、起 4 个 pthread（0x3a05f0/0x4217f8 等入口）
4. Activity 创建时 `q.onActivityCreated` → `t.a(2084711231, activity)`：传递当前 Activity
5. `idb.f.f()` → `j3.b(-1763556560)`；另有 `t.a(681473438)` 置就绪标志（写 `0x957440=1`）
6. 之后 `idb.f.h()` 的签名调用才会产出非 null 结果（native 侧就绪检查）

## 3. opcode 一览（jadx + 模拟实测对应）

| opcode | Java 包装 | 作用（证据） |
|---|---|---|
| -907571125 | `j3.a(long)` | 初始化 native→Java 桥缓存（写监视：0x9575a8/0x958138 等被写入） |
| 1012919688 | `j3.a(idb.c)` | SDK 配置：17 参 = appKey(f216194a)、appSecret(f216195b)、int、10×boolean、3×float、尾串 f216216w；native 随后采集 PackageInfo（packageName/versionName/firstInstallTime/lastUpdateTime/versionCode/applicationInfo）并经桥取 `ActivityThread.currentProcessName` 等 |
| 2084711231 | `j3.a(Object)` | 传入 Activity（桥问 "Activity" 类型） |
| **-1765467163** | `j3.b(...)` ← `idb.f.h` | **请求签名**：args={method, host, path, query, byte[] body} → `Map` |
| 1254421745 | `idb.f.e(int)` | 返回 `Map<String,Long>`（另一签名/时间类接口） |
| -111994510 | `q7` 字段初始化 | native 返回 Long 常量 **0x770f4e9 (=124622057)**，Java 字符串解密种子 |
| 1116798438 | `q7.a(bArr, bArr2)` | 对 byte[] **原地**做字符串解密变换（见 §6） |
| 681473438 | `j3` 内部 | 置 native 就绪标志 0x957440=1 |
| -1763556560 / -816881994 / -204833437 / 968431380 / -1438017 等 | 各处 | 初始化/心跳/上报类（未逐一展开） |

`-1765467163` 这类魔数的性质：是 **t.a/t.b 分发 switch 的 case 选择子**（t.b 的 74 个 case 全是这种随机外观整数），不是 appid/key index。应用身份由配置 opcode 1012919688 的 `f216194a`（appKey）承载，出现在 mua JSON 的 `"a"` 字段。

## 4. 签名算法（opcode -1765467163）实测还原

模拟输入：`method="GET"`, `host="edith.xiaohongshu.com"`, `path="/api/sns/v1/homefeed"`, `query="deviceId=abc123&ts=1700000000"`, `body=10 字节`。

### 4.1 输出（实测）

```json
{
  "x-mini-mua": "<base64url(JSON)>.<base64url(528字节blob)>",
  "x-mini-s1":  "<base64，62 字节>",
  "x-mini-sig": "<64 hex>"
}
```

实例（模拟环境确定性输出）：

```
x-mini-sig = 1d3475e5e935f58b92d391989060eef9f37bbebe3bbbdcb683c73ecc3b90ad8f
x-mini-s1  = AAEAAAABov1glOEH03M0V+jULBj2xIB0yfA1Chi01BKY9RxnDdeZi8GlqgrUp0ZGivpgtvXiCCUFUVJiggo=
           = 0001 || 00000001 || 54字节请求相关数据
x-mini-mua = base64url({"a":"test-string-value","c":1,
                        "k":"2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
                        "p":"a","s":"000…0(120个0)","v":"2.9.83"})
             + "." + base64url(528 字节 blob)
```

mua JSON 字段：`a`=appKey（配置 f216194a 原样填入）、`c`=1、`k`=32 字节密钥的 hex（见 §4.4）、`p`="a"(android)、`s`=60 字节值 hex（模拟环境中全 0，真实设备应有值，疑似设备/会话签名）、`v`="2.9.83"（Tiny SDK 版本）。

### 4.2 x-mini-sig（已破解 16/32 字节 + 整体结构）

内存中抓到签名原文（preimage，堆地址 0x6f38c0/0x6f3d60 两处副本）：

```
preimage = METHOD "\n" PATH "\n" QUERY "\n" hex(SHA256(body_buf)) "\n" x-mini-mua 完整值
x-mini-sig[16:32] = SHA256(preimage) 的后 16 字节（hex 后 32 字符）
```

- **HOST 不参与签名**（preimage 里没有 host）。
- `hex(SHA256(body_buf))`：native 侧会把 Java 传入的 body 数组**用 SetByteArrayRegion 原地清零**，然后对"与 body 等长的全零缓冲"做 SHA-256。两次不同 body 内容的实验（10B 与 20B）证实：hex64 = `SHA256(0x00 × bodyLen)`，**body 内容不影响签名，只影响长度**（证据：run1 `01d448af…`=sha256(10×00)，run2 `de47c9b2…`=sha256(20×00)，均与 Python 计算逐字节一致）。
- 后缀 16 字节在两组独立输入下均验证 `= SHA256(preimage)[16:]`（run1 `f37bbebe…`、run3 `d87903c3…`，与 Python sha256 完全一致）。SHA-256 原语证据：K 常量表 @ 文件 0x11d7a4（Ghidra 0x21d7a4）、H0 @ 0x10ed18；运行时在 0x6cbf18/0x6cc918/0x6c9544 观察到 SHA-256 初始状态写入。
- **x-mini-sig 的前 16 字节（hex 前 32 字符）：未完全解出。**已确证的性质：
  - 依赖完整 preimage（含 mua）：只改 mua 的 `"a"` 字段（part1 不变），前 16 字节改变；
  - ≠ `SHA256(preimage)[0:16]`；≠ MD5/SHA1(preimage)；≠ HMAC(k|config|q7key, preimage/part1)；≠ sha256(sha256(preimage)) 等约 40 种候选（全部两组样本联合验证排除）；
  - 运行时观察到大量 HMAC 形态的成对 SHA-256 init（0x6cbf18 与 0x6cc918 两处，16 次，长度 45/9/8 的小输入）——推测前 16 字节来自另一个 HMAC-SHA256 输出的截断，密钥/消息细节**不确定**。

### 4.3 x-mini-s1（部分解出）

62 字节 = `0x0001`(版本?) + `0x00000001` + 54 字节随请求变化的数据。54 字节段在不同 body/配置下均变化，疑似某种签名/加密输出（长度 54 ≈ 非标准，排除裸 RSA/ECC 典型长度），**具体算法不确定**。

### 4.4 x-mini-mua 第二段（528 字节 blob，未解出）

528 = 512 + 16，形态像 "RSA-4096 签名 + 16 字节 tag/校验"。全库无 AES S-box/Te 表、无 ARMv8 AESE/SHA 指令、无 SM2/SM3/SM4/secp256k1/P-256 常量——与"软件 bignum RSA（无表）"假设相容，但**未证实**。该 blob 在确定性模拟中随 mua JSON 内容变化。
`k`（mua JSON 中 32 字节密钥）在模拟中为常量 `2fe57da3…`，不随配置 appKey 或请求变化；推测由设备指纹 HMAC 链派生（签名过程实测发起 **57 次** Java 桥调用采集 Build 全字段/Version/SDK_INT/WifiManager/BatteryManager/AudioManager/ClassLoader/已装应用（如 `android.tencent.TencentCommon`）等设备指纹），**派生细节不确定**。
mua `"s"` 字段（60 字节）在模拟中全零：真实值疑依赖服务端下发或模拟环境缺失的会话数据，**不确定**。

### 4.5 签名伪代码（已确证部分）

```python
def tiny_sign(method, host, path, query, body: bytes, appKey, k, s):
    # —— native 侧行为（模拟实测）——
    body_buf = b"\x00" * len(body)           # native 将 Java body 数组清零后哈希等长零缓冲
    body_hex = sha256(body_buf).hex()        # 64 hex
    mua_json = json_compact({"a": appKey, "c": 1, "k": k.hex(), "p": "a",
                             "s": s.hex(), "v": "2.9.83"})   # 键按字母序
    mua = b64url(mua_json) + "." + b64url(blob528)          # blob528 算法未解出
    preimage = (method + "\n" + path + "\n" + query + "\n"
                + body_hex + "\n" + mua).encode()           # host 不参与
    digest = sha256(preimage)
    x_mini_sig = (head16.hex() + digest[16:].hex())         # head16 算法未解出
    return {"x-mini-mua": mua, "x-mini-s1": b64(s1_62B), "x-mini-sig": x_mini_sig}
```

## 5. 混淆与字符串加密

- **控制流**：函数碎片化 + 运行时间接跳转（跳转目标 = 表项/参数 ± 常量，如 `-0x3a25614`、`-0x3a3fbd8`、`-0x3edecec` 等，每个碎片一套）。JNI_OnLoad 真实体在 0x2b1154 之后。
- **指针加密**：数据段存储 `真实地址 + 常量`，重定位 addend 被混淆器改写（Ghidra 中 `[0x8cea30]=0x3cd6768` 即编码值）。
- **字符串**：.rodata/.data 静态密文，运行时按需解密（init_array 85 项 + 使用时解密）。
- **反模拟/反调试**：内联 `svc 0`（clock_gettime/gettid/fstatat 等）、多 pthread 看门狗、栈金丝雀（tpidr_el0+0x28）。

## 6. Java 侧字符串解密（q7/p7，opcode 1116798438）

jadx 中 `p7.f143058a.a(bytes, key)` 的 native 实现 = `t.a(1116798438, {Long seed, byte[] data, byte[] key})`，**原地**变换 `data`。seed = `t.a(-111994510)` 返回的常量 **0x770f4e9**。
对 `t.a(Object)` 中 `obj==null` 分支样本（输入 `AC 24 39 6A`、key `10 A8`，输出 "null"）逐字节反推，验证通过：

```
out[0] = in[0] + key[0]      (0xAC+0x10=0xBC;  后续 Java 再 -0x4E → 'n')
out[1] = in[1] ^ key[1]      (0x24^0xA8=0x8C;  后续 ^0xF9 → 'u')
out[2] = in[2] - key[0]      (0x39-0x10=0x29;  后续 ^0x45 → 'l')
out[3] = in[3] ^ key[1]      (0x6A^0xA8=0xC2;  后续 -0x56 → 'l')
```

即 **2 字节密钥循环 + [加, 异或, 减, 异或] 操作循环**的变体；seed(0x770f4e9) 的具体作用（选择操作表/扩展密钥）**不确定**，未完全展开。

## 7. libtinyd.so（134 KB）角色

与 libtiny 同一混淆器。`JNI_OnLoad @ 0x10a610` 实测注册：

| class | name | signature | fnPtr |
|---|---|---|---|
| `com/xingin/tiny/daemon/d` | `a` | `(I[Ljava/lang/Object;)Ljava/lang/Object;` | 0x10c4bc |

并缓存 `Map/ArrayList/Intent/Collection/Iterator` 及 **`android/os/Process.setArgV0Native(String)`**（改进程名）等 JNI 引用；导入表含 `fork/getprogname/syslog/openlog/pthread_*`。判定为 Tiny SDK 的**守护进程组件**（fork 子进程、改名伪装、看门狗/保活/反调试类用途），不参与签名计算。

## 8. 方法学与证据索引

- 模拟器：Unicorn 2.1.4，加载两段 PT_LOAD（base 0x100000 对齐 Ghidra），应用 45033 条 R_AARCH64_RELATIVE 与 191 条 PLT/GLOB_DAT（BRK stub + Python 侧 libc/JNI 实现，含真实 zlib deflate 桥接 Python `zlib`、SVC 系统调用桩、va_list 解析、Java `t.b` 语义仿真）。
- 关键函数地址（Ghidra）：JNI_OnLoad `0x2b045c`（跳板 `0x2b1154`）；native `t.a` 入口 `0x283df0`；GetEnv 包装 `FUN_0068e038`；桥调用 trampoline `FUN_0041aac0`；桥打包 `FUN_00692104`(5参)/`FUN_0069248c`(4参)；std::string append `FUN_0024ee90`/`FUN_0024f044`。
- 关键全局：`0x957438`(JavaVM*)、`0x957440`(就绪标志)、`0x9575a8/0x9575b0`(桥 cls/mid)、`0x958138/0x958148`(装箱辅助)、`0x9576b0` 起(装箱类缓存)、`0x957820` 起(PackageInfo 字段缓存)。
- 模拟器脚本：`/tmp/tiny-re/emu.py`（含全部桩与观测点）；Ghidra 辅助脚本：`/tmp/tiny-re/{Probe,Disas,ForceDecomp,Info,Xref}.java`。

## 9. 未决项汇总（明确不确定）

1. **x-mini-sig 前 16 字节**的具体哈希公式（已排除约 40 种候选；疑为某 HMAC-SHA256 截断，密钥可能依赖模拟环境缺失的材料）。
2. **mua 第二段 528 字节**与 **x-mini-s1 54 字节段**的密码学构造（疑似 RSA/签名类，无常量证据）。
3. mua `"k"` 的派生公式（疑设备指纹 HMAC 链）、`"s"` 的来源（模拟中为零）。
4. body 清零哈希是否为真实设备行为（模拟中所有 JNI 调用均已记录、native 确实未读 body 内容；但仍建议真机 Frida 复核一次 `SetByteArrayRegion` 前后数组内容）。
5. `x-s/x-t` 不在本库：归属 `libxyass.so`（未分析）。
