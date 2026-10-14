# 小红书签名 API 客户端（frida RPC 借 App 算签名）

在小红书 App 进程内注入 frida 脚本，借 App 自身的 native 能力实时计算签名头
（libtiny 的 `x-mini-*`、libxyass 的 `shield`/`xy-platform-info`），Python 侧拼 URL、
发 HTTP、解析 JSON。

支持两套目标（`XHS_TARGET` 环境变量或 CLI `--target` 选择）：

| 目标 | 设备 | 包名 | 注入方式 | frida 入口 |
| --- | --- | --- | --- | --- |
| `emu`（默认） | Android 12 模拟器 emulator-5554 | com.xingin.xhs（官方 v9.36.2） | frida-server（改名 `.kworker` + 端口 44444） | `127.0.0.1:44444` |
| `real` | 小米真机 101114e（Android 15，无 root） | com.xingin.xhsre（重打包 v9.36.2） | frida-gadget 17.23.3 打进 APK，主进程 `attachBaseContext` 加载，listen 127.0.0.1:27043，`on_load=wait` | `127.0.0.1:27043`（自动 `adb -s 101114e forward`） |

## 真机最新用法（2026-10-14 更新）

真机侧已换成 **gadget script-interaction + 反向 TCP**（内嵌脚本主动连 Mac 27045，
`adb reverse tcp:27045 tcp:27045`），主要 RPC：

| RPC | 用途 |
| --- | --- |
| `fetch(method,url,bodyB64,contentType)` | 借 App 的 edith OkHttpClient 执行（全真拦截器链，鉴权最强；有概率触发看门狗杀进程，客户端会自动重连重试） |
| `rawfetch(url, headersArr, bodyB64)` | 先 sign 算头再 HttpsURLConnection 从手机发出（稳定不死；guest 接口可用，登录态接口会被软拒"登录已过期"） |
| `setsession(sid, uid)` | 钩 `n2c.b` 的 `b()`/`c()` 注入登录态（TinyInterceptor 用 `header()` 覆盖 x-legacy-sid，注请求头没用）；sid 形如 `session.<id>`，客户端自动补前缀 |
| `userstate()` / `evaljs(code)` | 读 App 账号态 / 任意 Java 探针 |

**当前推荐用法（全程不碰手机）**：密码登录也走 appFetch 全链，200 拿 session 落盘，
之后每次 attach 自动 `setsession` 注入：

```bash
export XHS_PHONE='2895874976' XHS_PASSWORD='***'   # 凭据只走环境变量
python xhs_api.py --target real login --zone +1    # ✅ API 登录（单会话，会踢掉其他端）
python xhs_api.py --target real search "咖啡"       # ✅ 20 条真实结果含 xsec_token
python xhs_api.py --target real note <note_id> --xsec-token <token>   # ✅ 标题/正文/图片/评论
```

模拟器（--target emu）同样可用：默认也走 appFetch（Mac 直连已被风控判死，
`XHS_EMU_DIRECT=1` 仅用于调试签名）。emu 抖动大，失败重跑 1-3 次。

已知边界与未解项见 `docs/真机迁移与现场情况.md` 第六、七节（账号单会话互踢、
App 周期性无痕自杀由客户端重连兜底等）。

## 真机重打包（`~/re-targets/xhs-repack/`）

1. `apktool d -f xhs_base.apk -o decoded`（全量解包；`-r` 会连 AndroidManifest 也保持二进制，没法改包名）。
2. 修资源：apktool 3.0.3 解出的约 9300 个 layout XML 带 `xmlns:android=""` 这类空前缀声明，
   aapt2 拒绝（"must not undeclare prefix"）。脚本批量处理：前缀未被使用的声明删除，
   被使用的映射到合法命名空间（android→`apk/res/android`，其余→`apk/res-auto`）。
3. 清单改包名：`package`/`android:authorities`/`<permission>`/`uses-permission`/
   `android:permission` 里的 `com.xingin.xhs` → `com.xingin.xhsre`（组件类名不动），
   与手机上的官方包共存（互不覆盖、provider/权限不冲突）。
4. gadget：`libfrida-gadget.so` + `libfrida-gadget.config.so`（listen 127.0.0.1:27043、
   `on_load=wait`）放进 `lib/arm64-v8a/`；在
   `smali_classes10/com/xingin/xhs/app/XhsApplication.smali` 的 `attachBaseContext`
   开头注入 `System.loadLibrary("frida-gadget")`，并用
   `ActivityThread.currentProcessName()` 判断只在主进程加载（避免多进程抢端口）。
5. `zipalign` + `apksigner`（本地 debug.keystore）签名，安装：
   `adb -s 101114e install xhsre.apk`。
   **小米会弹"USB 安装确认"框，需要在手机上手动点允许**（弹窗约 15s 不点会自动取消，
   报 `INSTALL_FAILED_USER_RESTRICTED`）。
6. libxyass 有 APK 签名校验（signatures hashCode 白名单，不通过 abort）：sign.js 在
   重打包包（包名≠com.xingin.xhs）里自动 hook `android.content.pm.Signature.hashCode`
   返回原包证书值 `-1083242518`（由原 APK v2 签名块证书 DER 算 `Arrays.hashCode`）。

## 文件

| 文件 | 说明 |
| --- | --- |
| `sign.js` | frida 脚本。`rpc.exports`：`sign(method, url, bodyB64)`（空串=无 body，POST 传 base64 body）、`status()`、`rotateshield()`、`loginparams()`（借 App 现算登录设备参数）、`debugurls()`/`debugresp()` |
| `xhs_api.py` | Python 客户端 + CLI（含密码登录与 session 持久化） |
| `session.json` | 登录成功后自动生成的登录态（session/userid/secure_session），客户端启动自动加载 |
| `header-template.json` | 真实请求样本头（User-Agent/Referer 等）。JS 侧还没抓到样本时 Python 用它兜底，抓一次自动更新 |
| `java-bridge.js` | frida 17 不再内建的 Java 桥（取自 frida-tools 14.11，`frida:load-bridge` 协议按需加载） |
| `_probe.py` | 排障工具：`_probe.py <script.js> [秒]`，attach 后注入任意 JS 观察输出 |

## 前置条件（关键：frida-server 必须隐藏）

App 看门狗会探测 frida 并自杀（实测：检测到后调 `_exit(0)` 干净退出）。两层对策：

1. **frida-server 改名 + 非默认端口**（否则 App 启动后不久即被杀）：

   ```bash
   export ANDROID_SDK_ROOT=/opt/homebrew/share/android-commandlinetools
   ADB=$ANDROID_SDK_ROOT/platform-tools/adb
   $ADB push ~/re-targets/frida-server /data/local/tmp/.kworker
   $ADB shell "chmod 755 /data/local/tmp/.kworker"
   $ADB shell "nohup /data/local/tmp/.kworker -l 127.0.0.1:44444 >/dev/null 2>&1 &"
   $ADB forward tcp:44444 tcp:44444
   ```

2. **封堵自杀调用**：`sign.js` 加载第一时间把 libc `exit`/`_exit` 替换为"线程睡死"
   （看门狗线程调 `_exit(0)` 时被拦下，进程存活）。spawn 模式下脚本在 App 代码
   运行前注入，封堵先生效。

Python 侧默认连 `127.0.0.1:44444`（`xhs_api.py` 会自动补 `adb forward`）。
可用环境变量覆盖：`XHS_FRIDA_HOST=usb`（不推荐，默认端口/名字会被盯杀）。

## 用法

```bash
cd ~/re-targets/xhs-out/client
PY=~/re-targets/venv/bin/python

# 模拟器（默认；或显式 --target emu）
$PY xhs_api.py status            # 只看签名组件就绪状态
$PY xhs_api.py basic             # 未登录首页 feed（/api/sns/v1/note/basic/homefeed）
$PY xhs_api.py login --zone 1 --phone <手机号> --password <明文密码>
$PY xhs_api.py search "咖啡"      # 搜索（需登录态，见下）
$PY xhs_api.py note <note_id>    # 图文详情 imagefeed（需登录态）
$PY xhs_api.py homefeed          # 正式首页 feed（需登录态）
$PY xhs_api.py --no-spawn basic  # 不 spawn，对已在运行的 App attach

# 真机（重打包包 com.xingin.xhsre，gadget 形态）
$PY xhs_api.py --target real status
$PY xhs_api.py --target real basic
$PY xhs_api.py --target real login --zone 1 --phone <手机号> --password <明文密码>
$PY xhs_api.py --target real search "咖啡"
# 也可用环境变量：XHS_TARGET=real $PY xhs_api.py basic
```

## POST 与密码登录

- **POST 签名**：`sign("POST", url, bodyB64)`——body 同时进 tiny（`idb.f.h` 的
  byte[] 参数；注意 native 会原地清零该数组，shield 用的是另一份拷贝）和 shield
  canonical（假 chain 的 `request()` 里用 `RequestBody.create(MediaType, byte[])`
  + `Builder.method("POST", body)` 现造 Request）。
- **登录**：`login_password(zone, phone, password)` 把明文密码按 App 逻辑
  `MD5(UTF-8).hex` 小写后，连同借 App `fr.b0.a()`/`is.a0.a()`/`is.a0.b()` 现算的
  约 19 项设备参数（android_id/oaid/gaid/mac/install_time/ruleId/source 等，经
  `loginparams` RPC 获取）一起 form 提交到 `/api/sns/v4/user/login/password`。
- **session 持久化**：登录成功把 `data.session`/`userid`/`secure_session` 写入
  `session.json`；之后每次请求 `sign()` 返回头后用该 session 覆盖 `x-legacy-sid`
  （tiny/shield 的签名摘要都不含此头，覆盖安全）。客户端启动自动加载。

代码调用：

```python
from xhs_api import XhsClient
c = XhsClient()                       # spawn App、注入、等待签名组件就绪
r = c.basic_homefeed()                # requests.Response
notes = r.json()['data']
r = c.search_notes('咖啡', page=1)
r = c.get_note('<note_id>')
```

## 签名头组装（sign.js 内部）

1. `x-mini-mua/x-mini-s1/x-mini-sig/x-mini-gid`：反射调 `idb.f.h(method, url, body)`（libtiny）。
2. `x-legacy-did` = `mhb.r.e()`；`x-legacy-fid` = `hjc.n1` 单例 `d()`；
   `x-legacy-sid` = `n2c.b` 单例 `b()`。
3. `xy-common-params`：`b9b.a` 单例 `b(jjc.e.M.getValue(), null)`（反射 invoke）。
4. `shield`/`xy-platform-info`：`Java.registerClass` 造假 `okhttp3.Interceptor$Chain`，
   调捕获的 `XhsHttpInterceptor` 实例 `intercept(fakeChain)`，从 proceed 截获的请求里读出头。
   假请求的 `xy-*` 头（目前只有 `xy-common-params`）会进入 shield canonical，已按此构造。
5. `User-Agent` 等静态头：hook `okhttp3.internal.http.RealInterceptorChain.proceed`
   抓真实请求样本做模板补齐（注意：此版本 okhttp 被官方改过，类在 `internal.http`
   而不是 `internal.connection`）。JS 侧还没抓到样本时，Python 用
   `header-template.json`（之前抓的 19 头样本，含 `User-Agent: Dalvik/...`、
   `Referer: https://app.xhs.cn/`）兜底补齐。

## 已验证的链路（模拟器 App 未登录状态）

| 链路 | 结果 |
| --- | --- |
| `GET /api/sns/v1/note/basic/homefeed`（未登录降级首页） | **200 + `code:0`**，返回真实笔记列表（可反复调用） |
| `POST /api/sns/v4/user/login/password`（密码登录） | **POST 签名链路本身打通**（带齐约 19 项设备参数到达风控判定）。多次实测在三种形态间波动：`461 + code:300012 "IP存在风险"`、`code:300015 "浏览器运行环境异常"`、`406 + xy-ter-str`（shield 密钥挑战，轮换后仍 406）。同一 shield 密钥上午拿 `-100`、下午拿 `406`，判定为**服务端风控评分随时段波动**，非签名问题 |
| `GET /api/sns/v10/search/notes`（搜索） | 200 + `code:-100 登录已过期`（长寿实例）/ 406 + `{"code":0,"data":{}}`（新实例） |
| `GET /api/sns/v1/note/imagefeed`（图文详情） | 同上：-100 或 406 |
| `GET /api/sns/v6/homefeed`（正式首页） | 同上：-100 或 406 |

结论：**GET/POST 签名体系（tiny+shield+legacy+common-params）均已被服务端接受**——
同一套签名管线在 basic homefeed 上稳定拿到 200+业务数据；登录请求带完整设备
参数到达风控判定（返回具体风控码，而非参数/签名错误）。搜索/详情/登录卡住的都是
**账号与风控门**（未登录、模拟器指纹、出口 IP 被标记），不是签名问题。
新实例上观察到的 `406 + xy-ter-str` 是 libxyass 的密钥轮换挑战（shield 文档 §7）：
客户端已实现轮换（xy-ter-str 写 SP + 新建 interceptor 实例，见 `rotateshield` RPC），
但该设备/账号状态下服务端轮换后依旧 406——真实 App 的 native 逻辑面对同样的
响应也会得到同样结果。换可靠网络环境登录成功后，`session.json` 持久化的登录态
即可驱动搜索/详情链路。

## 406 与 shield 密钥

- shield 的 hmac key 存于 App `shared_prefs/s.xml` 的 `<token>_hmac`（本机 token 为
  `main`）。服务端可通过 `406 + xy-ter-str` 响应头下发新密钥。
- `xhs_api.py` 的 `get()` 遇到 406+xy-ter-str 会自动调 `rotateshield` RPC 轮换并重试
  （最多 2 次）。
- 注意：不要给 native 喂"假 406 响应"骗它自己轮换——native 会对旧响应 `close()`，
  无 body 的 dummy Response 抛 `IllegalStateException`，JNI 层直接 abort
  （留过 tombstone）。当前采用写 SP + 新建实例的方案。

## 已知限制

- POST 已支持（form/任意字节 body）；Content-Type 目前固定按 form-urlencoded 构造
  shield 假请求，如需 JSON body 调 `sign.js` 里的 `gFakeBodyType`。
- 登录被风控挡住（300012 IP 风险 / 300015 环境异常 / 406 密钥挑战，三者随时段波动）：
  需换可靠网络环境（住宅 IP / 非机房出口）后重试 `login`；登录态一旦拿到会持久化在
  `session.json`。
- 看门狗检测有升级迹象：现在偶发用"构造野指针 SIGSEGV"方式杀进程（不再是干净的
  `_exit(0)`，无法靠封堵 exit 拦住）。客户端已做进程死亡自动重 attach + 请求级重试，
  会话状态全部落盘，单次操作可在进程存活窗口内完成。
- `x-b3-traceid`/`x-xray-traceid` 等每请求随机头不生成（服务端未因此拒绝）。
- `Interceptor.replace` 的封堵在同一个 App 进程里只能装一次；重复 attach 同进程时
  脚本会提示 "already replaced this function"（无害，说明封堵仍在）。

## 排障

- `_probe.py /tmp/xxx.js 10`：注入任意脚本观察 console 输出与进程存活。
- `xhs_api.py status` 的 JSON 里 `errors` 字段有各组件最近一次异常。
- App 进程会 `prctl` 改名为 `rednote`，frida 进程枚举里看不到 `com.xingin.xhs`，
  客户端用 `adb shell pidof com.xingin.xhs` 取 pid 再 attach。
- jadx 里 `f216243e`/`f205613a` 这类名字是 jadx 对同名字段的消歧后缀，
  运行时字段名是最后一个字母；且这些类字段与方法同名，frida 桥优先解析成方法，
  所以 sign.js 里字段/方法访问大量走反射。
- 反射 `Method.invoke` 返回的对象包装器按声明类型 `Object` 解析方法，
  需 `Java.cast` 回真实类型（见 `javaMapToObj`）。
