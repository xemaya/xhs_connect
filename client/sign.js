/*
 * 小红书 v9.36.2（com.xingin.xhs）签名 RPC
 * 借 App 自身 native 能力算签名：
 *   - tiny（libtiny.so）：idb.f.h(method, url, body) -> x-mini-mua / x-mini-s1 / x-mini-sig
 *   - shield（libxyass.so）：XhsHttpInterceptor.intercept(fakeChain) -> shield / xy-platform-info
 *   - x-legacy-did/fid/sid、xy-common-params 走 Java 层静态/单例调用
 *   - User-Agent 等静态头来自对真实请求的样本抓取（RealInterceptorChain.proceed hook）
 *
 * 反检测：App 看门狗发现 frida agent 后会调 _exit(0) 自杀（实测），
 * 脚本加载时第一时间把 libc 的 exit/_exit 替换为"睡死调用线程"，保住进程。
 * 配套措施：frida-server 需改名（如 .kworker）+ 非默认端口运行，否则 App 启动即被盯杀。
 *
 * rpc.exports:
 *   sign(method, url, bodyB64) -> {headers: {...}, meta: {...}}   bodyB64 为空串表示无 body
 *   status()                   -> 各组件就绪状态
 *   debugUrls()                -> 最近抓到的 edith 请求 URL（排障用）
 */

/* ---------- 反自杀（必须在脚本加载第一时间装，不依赖 Java） ---------- */
(function blockSuicide() {
  var seen = {};
  ['exit', '_exit', '_Exit'].forEach(function (name) {
    var addr = Module.findGlobalExportByName(name);
    if (!addr || seen[addr.toString()]) return;
    seen[addr.toString()] = 1;
    try {
      Interceptor.replace(addr, new NativeCallback(function (code) {
        console.log('[sign] 拦截到自杀调用 ' + name + '(' + code + ')，线程睡死');
        Thread.sleep(24 * 3600);
      }, 'void', ['int']));
      console.log('[sign] 已封堵 ' + name + ' @ ' + addr);
    } catch (e) {
      console.log('[sign] 封堵 ' + name + ' 失败：' + e);
    }
  });
  // 重打包签名校验失败时走的是 abort()（SIGABRT，匿名内存里的解密代码）。
  // abort 不做清理，直接返回即可"失败开放"——调用方当作没事继续跑。
  var abortAddr = Module.findGlobalExportByName('abort');
  if (abortAddr && !seen[abortAddr.toString()]) {
    try {
      Interceptor.replace(abortAddr, new NativeCallback(function () {
        console.log('[sign] 拦截到 abort()，吞掉（签名校验失败开放）');
      }, 'void', []));
      console.log('[sign] 已封堵 abort @ ' + abortAddr);
    } catch (e) {
      console.log('[sign] 封堵 abort 失败：' + e);
    }
  }
})();

/* ---------- Java 桥手动加载（frida 17 不再内建，复刻 frida-tools REPL 的做法） ---------- */
(function loadJavaBridge() {
  if (typeof Java !== 'undefined') return;
  send({ type: 'frida:load-bridge', name: 'java' });
  recv('frida:bridge-loaded', function (msg) {
    Script.evaluate('/frida/bridges/' + msg.filename,
      '(function () { ' + [msg.source,
        "Object.defineProperty(globalThis, 'Java', { value: bridge });",
        'return bridge;'].join('\n') + ' })();');
  }).wait();
  console.log('[sign] java 桥已加载：' + (typeof Java));
})();

/* ---------- 重打包包骗过 libxyass 的 APK 签名校验 ---------- */
// libxyass initializeNative 会 getPackageInfo(自包名).signatures[].hashCode()
// 比对硬编码白名单，不通过就 abort()。重打包换了签名，这里把 Signature.hashCode
// 钩成原包的值（由原 APK v2 签名块证书 DER 算 Arrays.hashCode 得到）。
(function maybeHookSignature() {
  var ORIG_SIG_HASHCODE = -1083242518;  // 官方 v9.36.2 证书
  try {
    // 用 /proc/self/cmdline 判包名（此时 Application 可能还没建好）
    var f = new File('/proc/self/cmdline', 'r');
    var buf = new Uint8Array(64);
    var n = f.readBytes(buf);
    f.close();
    var pkg = '';
    for (var i = 0; i < n && buf[i] !== 0; i++) pkg += String.fromCharCode(buf[i]);
    if (pkg === 'com.xingin.xhs') return;  // 官方包不用 hook
    Java.perform(function () {
      Java.use('android.content.pm.Signature').hashCode.implementation = function () {
        return ORIG_SIG_HASHCODE;  // Java int 是有符号 32 位，直接给负值（>>>0 超界会被桥拒绝）
      };
      console.log('[sign] 重打包包（' + pkg + '），Signature.hashCode 已钩为 ' + ORIG_SIG_HASHCODE);
    });
  } catch (e) { console.log('[sign] hook Signature.hashCode 失败：' + e); }
})();

var S = {
  shieldInstances: [],      // 捕获到的 XhsHttpInterceptor 存活实例
  shieldHookOk: false,      // intercept 实例捕获 hook 是否装好
  sampleHookOk: false,      // 样本抓取 hook 是否装好
  sampleHeaders: null,      // 真实请求头样本 [[name, value], ...]（取头最多的一份）
  sampleUrl: null,
  recentUrls: [],           // 最近见过的 edith URL（最多 20 条）
  recentResp: [],           // 最近 edith 响应 [url, code]（最多 30 条，排障用）
  fakeChainCls: null,       // Java.registerClass 的假 Interceptor.Chain
  lastErr: {},
  shieldWarn: null,
};

function log(m) { console.log('[sign] ' + m); }

/* ---------- base64 解码（Python 侧传 body 用） ---------- */
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64decode(s) {
  var out = [];
  var clean = String(s).replace(/=+$/, '');
  var acc = 0, nbits = 0;
  for (var i = 0; i < clean.length; i++) {
    var v = B64C.indexOf(clean[i]);
    if (v < 0) continue;
    acc = (acc << 6) | v; nbits += 6;
    if (nbits >= 8) { nbits -= 8; out.push((acc >> nbits) & 0xff); }
  }
  return out;
}

/* ---------- Java Map<String,String> -> JS object ---------- */
function javaMapToObj(map) {
  var obj = {};
  if (map === null) return obj;
  // 反射 invoke 返回的包装器按声明类型 Object 解析方法，先 cast 回 HashMap
  var hm = Java.cast(map, Java.use('java.util.HashMap'));
  var keys = hm.keySet().toArray();
  for (var i = 0; i < keys.length; i++) {
    var k = '' + keys[i];
    obj[k] = '' + hm.get(keys[i]);
  }
  return obj;
}

/* ---------- 假 Interceptor.Chain（给 shield native 用） ---------- */
// 注意 frida 桥的两个坑（实测）：
//  1. registerClass 实现里返回“别处造好存全局”的 Java 对象会被判定类型不兼容，
//     必须在 request() 实现里现造 Request；
//  2. 实现方法收到的参数是借用包装器，想留到调用结束后用必须 Java.retain。
var gFakeUrl = null;
var gFakeMethod = 'GET';
var gFakeHeaders = [];       // [[name, value], ...]（只放 xy-* 头）
var gFakeBody = null;        // JS byte 数组或 null（POST 用）
var gFakeBodyType = 'application/x-www-form-urlencoded; charset=utf-8';
var gCapturedReq = null;

function ensureFakeChainCls() {
  if (S.fakeChainCls) return S.fakeChainCls;
  var Chain = Java.use('okhttp3.Interceptor$Chain');
  var ResponseBuilder = Java.use('okhttp3.Response$Builder');
  var Protocol = Java.use('okhttp3.Protocol');
  var RequestBuilder = Java.use('okhttp3.Request$Builder');
  var MediaType = Java.use('okhttp3.MediaType');
  var RequestBody = Java.use('okhttp3.RequestBody');
  // okhttp 版本差异：MediaType.parse（3.x）可能叫 get（4.x）；逐个试
  var mtFn = null;
  try { MediaType.parse(gFakeBodyType); mtFn = 'parse'; }
  catch (e) { MediaType.get(gFakeBodyType); mtFn = 'get'; }
  S.fakeChainCls = Java.registerClass({
    name: 'com.re.xhs.FakeChain',
    implements: [Chain],
    methods: {
      request: {
        returnType: 'okhttp3.Request', argumentTypes: [],
        implementation: function () {
          var rb = RequestBuilder.$new().url(gFakeUrl);
          for (var i = 0; i < gFakeHeaders.length; i++) {
            rb.header(gFakeHeaders[i][0], gFakeHeaders[i][1]);
          }
          if (gFakeBody !== null) {
            var mt = MediaType[mtFn](gFakeBodyType);
            // 直接按参数类型让桥自动选 create 重载（MediaType, byte[]）
            var body = RequestBody.create(mt, Java.array('byte', gFakeBody));
            return rb.method(gFakeMethod, body).build();
          }
          return rb.method(gFakeMethod, null).build();
        }
      },
      proceed: {
        returnType: 'okhttp3.Response', argumentTypes: ['okhttp3.Request'],
        implementation: function (req) {
          gCapturedReq = Java.retain(req);
          return ResponseBuilder.$new()
            .request(req)
            .protocol(Protocol.HTTP_1_1.value)
            .code(200)
            .message('OK')
            .build();
        }
      },
      call: {
        returnType: 'okhttp3.Call', argumentTypes: [],
        implementation: function () { return null; }
      },
      connection: {
        returnType: 'okhttp3.Connection', argumentTypes: [],
        implementation: function () { return null; }
      },
      connectTimeoutMillis: {
        returnType: 'int', argumentTypes: [],
        implementation: function () { return 0; }
      },
      readTimeoutMillis: {
        returnType: 'int', argumentTypes: [],
        implementation: function () { return 0; }
      },
      writeTimeoutMillis: {
        returnType: 'int', argumentTypes: [],
        implementation: function () { return 0; }
      },
      withConnectTimeout: {
        returnType: 'okhttp3.Interceptor$Chain', argumentTypes: ['int', 'java.util.concurrent.TimeUnit'],
        implementation: function (i, u) { return this; }
      },
      withReadTimeout: {
        returnType: 'okhttp3.Interceptor$Chain', argumentTypes: ['int', 'java.util.concurrent.TimeUnit'],
        implementation: function (i, u) { return this; }
      },
      withWriteTimeout: {
        returnType: 'okhttp3.Interceptor$Chain', argumentTypes: ['int', 'java.util.concurrent.TimeUnit'],
        implementation: function (i, u) { return this; }
      }
    }
  });
  return S.fakeChainCls;
}

/* ---------- hook 安装（幂等，status 轮询时重试） ---------- */
function addShieldInstance(inst) {
  var h = inst.hashCode();
  for (var i = 0; i < S.shieldInstances.length; i++) {
    if (S.shieldInstances[i].hashCode() === h) return;
  }
  if (S.shieldInstances.length >= 8) S.shieldInstances.shift();
  S.shieldInstances.push(inst);
  log('捕获 XhsHttpInterceptor 实例 #' + h + '（共 ' + S.shieldInstances.length + ' 个）');
}

function ensureHooks(tinyReady) {
  // 1) shield 实例捕获：先 Java.choose 捞现存实例（不会触发类初始化），
  //    确认类已被 App 自己加载后再 Java.use 装 hook（避免提前触发 static init）
  if (!S.shieldHookOk && tinyReady) {
    try {
      Java.choose('com.xingin.shield.http.XhsHttpInterceptor', {
        onMatch: function (inst) { addShieldInstance(inst); },
        onComplete: function () {}
      });
    } catch (e) { S.lastErr.chooseShield = '' + e; }
    if (S.shieldInstances.length > 0) {
      try {
        var X = Java.use('com.xingin.shield.http.XhsHttpInterceptor');
        X.intercept.implementation = function (chain) {
          addShieldInstance(this);
          return this.intercept(chain);
        };
        S.shieldHookOk = true;
        log('shield intercept hook 已安装');
      } catch (e) { S.lastErr.hookShield = '' + e; }
    }
  }
  // 2) 真实请求样本抓取（okhttp 内部类，提前 Java.use 无上下文依赖，但统一等 tiny 就绪后装）
  if (!S.sampleHookOk && tinyReady) {
    try {
      var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
      var impl = function (req) {
        var isEdith = false;
        var u = '';
        try {
          u = req.url().toString();
          isEdith = u.indexOf('edith.xiaohongshu.com') >= 0;
          if (isEdith) {
            if (S.recentUrls.indexOf(u) < 0) {
              S.recentUrls.push(u);
              if (S.recentUrls.length > 20) S.recentUrls.shift();
            }
            var h = req.headers();
            if (!S.sampleHeaders || h.size() > S.sampleHeaders.length) {
              var arr = [];
              for (var i = 0; i < h.size(); i++) arr.push([h.name(i), h.value(i)]);
              S.sampleHeaders = arr;
              S.sampleUrl = u;
              log('样本头已更新（' + arr.length + ' 个，来自 ' + u.split('?')[0] + '）');
            }
          }
        } catch (e) { /* 样本抓取失败不影响请求 */ }
        var resp = this.proceed(req);
        if (isEdith) {
          try {
            var last = S.recentResp[S.recentResp.length - 1];
            if (!last || last[0] !== u) {
              S.recentResp.push([u.split('?')[0], resp.code()]);
              if (S.recentResp.length > 30) S.recentResp.shift();
            }
          } catch (e) {}
        }
        return resp;
      };
      var m = RIC.proceed;
      try { m.overload('okhttp3.Request').implementation = impl; }
      catch (e) { m.implementation = impl; }
      S.sampleHookOk = true;
      log('RealInterceptorChain.proceed hook 已安装');
    } catch (e) { S.lastErr.hookSample = '' + e; }
  }
}

/* ---------- 各签名组件 ---------- */
// jadx 的 f216243e/f205613a/f16470a 等名字是 jadx 消歧后缀，运行时字段名是最后一个字母；
// 且这些类里字段与方法同名（桥优先解析成方法），所以一律走反射取字段。
function getStaticField(clsName, fieldName) {
  var f = Java.use(clsName).class.getDeclaredField(fieldName);
  f.setAccessible(true);
  return f.get(null);
}

function tinyReadyNow() {
  var f = Java.use('idb.f').class.getDeclaredField('e');
  f.setAccessible(true);
  return f.getBoolean(null) === true;
}

function tinySign(method, url, bodyB64) {
  try {
    // idb.f 里静态字段 h(CountDownLatch) 与静态方法 h(String,String,byte[]) 同名，走反射
    var cls = Java.use('idb.f').class;
    var m = cls.getDeclaredMethod('h', [
      Java.use('java.lang.String').class,
      Java.use('java.lang.String').class,
      Java.use('[B').class]);
    m.setAccessible(true);
    var bodyArr = bodyB64 ? b64decode(bodyB64) : [];
    var map = m.invoke(null, [method, url, Java.array('byte', bodyArr)]);
    if (map === null) throw new Error('tiny 未就绪（h() 返回 null）');
    return javaMapToObj(map);
  } catch (e) {
    console.log('[sign] tinySign 内部错误：' + e + '\n' + (e && e.stack ? e.stack : ''));
    throw e;
  }
}

function legacyHeaders() {
  var out = {};
  try { out['x-legacy-did'] = '' + Java.use('mhb.r').e(); }
  catch (e) { S.lastErr.did = '' + e; }
  try {
    var n1 = getStaticField('hjc.n1', 'a');
    var md = Java.use('hjc.n1').class.getDeclaredMethod('d', []);
    md.setAccessible(true);
    out['x-legacy-fid'] = '' + md.invoke(n1, []);
  } catch (e) { S.lastErr.fid = '' + e; }
  try {
    var sid = null;
    Java.choose('n2c.b', {
      onMatch: function (i) { sid = '' + i.b(); return 'stop'; },
      onComplete: function () {}
    });
    if (sid !== null) out['x-legacy-sid'] = sid;
  } catch (e) { S.lastErr.sid = '' + e; }
  return out;
}

function getCommonParams() {
  // jjc/e.java:133 的原样调用：b9b.a.f16470a.b(jjc.e.M.getValue(), null)
  // b9b.a 里静态字段 b(String "xy-common-params") 与实例方法 b() 同名，桥会优先解析成字段，
  // 所以方法也必须走反射 invoke。
  var E = Java.use('jjc.e');
  var inst = E.M.value.getValue();
  var aInst = getStaticField('b9b.a', 'a');
  var m = Java.use('b9b.a').class.getDeclaredMethod('b',
    [Java.use('y7b.a').class, Java.use('okhttp3.Request').class]);
  m.setAccessible(true);
  return '' + m.invoke(aInst, [inst, null]);
}

function shieldSign(method, url, extraHeaders, bodyArr) {
  ensureFakeChainCls();
  var lastErr = null;
  for (var idx = 0; idx < S.shieldInstances.length; idx++) {
    var inst = S.shieldInstances[idx];
    try {
      gFakeUrl = url;
      gFakeMethod = method;
      gFakeBody = (bodyArr && bodyArr.length > 0) ? bodyArr : null;
      gFakeHeaders = [];
      // shield canonical 会把请求里所有 xy-* 头纳入哈希，必须与最终请求一致
      var keys = Object.keys(extraHeaders || {});
      for (var k = 0; k < keys.length; k++) {
        if (keys[k].toLowerCase().indexOf('xy-') === 0) {
          gFakeHeaders.push([keys[k], '' + extraHeaders[keys[k]]]);
        }
      }
      gCapturedReq = null;
      var chain = S.fakeChainCls.$new();
      inst.intercept(chain);
      if (gCapturedReq === null) throw new Error('fake chain 的 proceed 未被调用');
      var h = gCapturedReq.headers();
      var out = {};
      for (var i = 0; i < h.size(); i++) {
        var n = h.name(i).toLowerCase();
        if (n === 'shield' || n === 'xy-platform-info') out[h.name(i)] = '' + h.value(i);
      }
      if (!out.shield) throw new Error('该实例未产出 shield 头（predicate 可能不匹配）');
      S.lastShieldInst = inst;
      return out;
    } catch (e) {
      lastErr = e;
      S.lastErr.shieldInst = 'inst#' + idx + ': ' + e;
    }
  }
  throw lastErr || new Error('没有可用的 shield 实例');
}

/* ---------- 登录设备参数（借 App 的 fr.b0/is.a0 现算） ---------- */
// 对应 n78/e.java 密码登录 V2 的参数组装：
//   b0.f187779a.a(map); is.a0.f220535a.a(map); is.a0.b(map)
function getLoginParams() {
  var MapCls = Java.use('java.util.Map').class;
  var map = Java.use('java.util.LinkedHashMap').$new();
  var b0 = getStaticField('fr.b0', 'a');
  var ma = Java.use('fr.b0').class.getDeclaredMethod('a', [MapCls]);
  ma.setAccessible(true);
  ma.invoke(b0, [map]);
  var a0 = getStaticField('is.a0', 'a');
  var ma0 = Java.use('is.a0').class.getDeclaredMethod('a', [MapCls]);
  ma0.setAccessible(true);
  ma0.invoke(a0, [map]);
  var mb0 = Java.use('is.a0').class.getDeclaredMethod('b', [MapCls]);
  mb0.setAccessible(true);
  mb0.invoke(null, [map]);
  return javaMapToObj(map);
}

/* ---------- shield 密钥轮换（服务端 406 + xy-ter-str 时调用） ---------- */
// 复刻 libxyass 的密钥更新：xy-ter-str 写入 SP "s" 的 token+"_hmac"，
// 再新建一个 XhsHttpInterceptor 实例（构造时 Native.initialize 读 SP 重新解析密钥）并优先使用。
// 注：不采用"假 406 响应骗 native 自己轮换"的方案——native 会对假响应 close()，
// 无 body 的 dummy Response 会抛 IllegalStateException 导致 JNI abort（实测有 tombstone）。
function rotateShield(xyterstr) {
  var cls = Java.use('com.xingin.shield.http.XhsHttpInterceptor');
  var inst = S.lastShieldInst || S.shieldInstances[0];
  if (!inst) throw new Error('没有可参考的 shield 实例');
  var fToken = cls.class.getDeclaredField('token');
  fToken.setAccessible(true);
  var token = '' + fToken.get(inst);
  var ctx = Java.use('android.app.ActivityThread').currentApplication();
  ctx.getSharedPreferences('s', 0).edit().putString(token + '_hmac', xyterstr).commit();
  var fresh = cls.$new(token, null);
  S.shieldInstances.unshift(fresh);   // 优先用新密钥实例
  S.lastShieldInst = fresh;
  log('shield 密钥已轮换（token=' + token + '）');
  return true;
}

/* ---------- 模板静态头（样本里不好直接算的字段） ---------- */
var TEMPLATE_SKIP = {
  'host': 1, 'connection': 1, 'content-length': 1, 'content-type': 1,
  'accept-encoding': 1, 'transfer-encoding': 1,
  'shield': 1, 'xy-platform-info': 1, 'xy-common-params': 1,
  'x-mini-mua': 1, 'x-mini-s1': 1, 'x-mini-sig': 1, 'x-mini-gid': 1,
  'x-legacy-did': 1, 'x-legacy-fid': 1, 'x-legacy-sid': 1,
  'x-b3-traceid': 1, 'x-b3-spanid': 1, 'x-b3-sampled': 1, 'x-xray-traceid': 1,
  'traceparent': 1, 'x-trace-id': 1
};

function applyTemplate(headers) {
  if (!S.sampleHeaders) return;
  var have = {};
  Object.keys(headers).forEach(function (k) { have[k.toLowerCase()] = 1; });
  for (var i = 0; i < S.sampleHeaders.length; i++) {
    var n = S.sampleHeaders[i][0];
    var ln = n.toLowerCase();
    if (TEMPLATE_SKIP[ln] || have[ln]) continue;
    headers[n] = S.sampleHeaders[i][1];
    have[ln] = 1;
  }
}

/* ---------- 主流程 ---------- */
function doSign(method, url, bodyB64) {
  method = (method || 'GET').toUpperCase();
  var headers = {};
  var meta = {};

  // 1) tiny（x-mini-* 头）；注意 native 会原地清零 body 数组，必须最先算
  try { Object.assign(headers, tinySign(method, url, bodyB64)); meta.tiny = true; }
  catch (e) { throw new Error('[step:tiny] ' + e); }

  // 2) x-legacy-*
  try { Object.assign(headers, legacyHeaders()); meta.legacy = true; }
  catch (e) { throw new Error('[step:legacy] ' + e); }

  // 3) xy-common-params（每次现算，含 t 时间戳）
  try { headers['xy-common-params'] = getCommonParams(); meta.commonParams = true; }
  catch (e) { S.lastErr.commonParams = '' + e; meta.commonParams = false; }

  // 4) shield（xy-* 头参与 canonical，所以放在 xy-common-params 之后）
  // body 同时进 tiny 与 shield 的摘要；tiny 的 native 会清零它收到的那个 Java 数组，
  // 这里重新解一份给 shield，互不影响
  var bodyArr = bodyB64 ? b64decode(bodyB64) : null;
  try { Object.assign(headers, shieldSign(method, url, headers, bodyArr)); meta.shield = true; }
  catch (e) { throw new Error('[step:shield] ' + e + '\n' + (e && e.$stack ? e.$stack : '')); }

  // 5) 模板静态头补齐（User-Agent 等）
  applyTemplate(headers);
  meta.template = !!S.sampleHeaders;

  return { headers: headers, meta: meta };
}

function computeStatus() {
  var st = { errors: S.lastErr };
  try {
    st.tinyReady = tinyReadyNow();
  } catch (e) { st.tinyReady = false; S.lastErr.tinyCls = '' + e; }
  ensureHooks(st.tinyReady);
  st.shieldInstances = S.shieldInstances.length;
  st.shieldHookOk = S.shieldHookOk;
  if (S.shieldHookOk) {
    try {
      st.shieldClassInit = Java.use('com.xingin.shield.http.XhsHttpInterceptor').initialized.value === true;
    } catch (e) { st.shieldClassInit = false; S.lastErr.shieldCls = '' + e; }
  } else {
    st.shieldClassInit = false;
  }
  st.sampleCaptured = !!S.sampleHeaders;
  st.sampleUrl = S.sampleUrl;
  try {
    var cp = getCommonParams();
    st.commonParamsOk = !!cp;
    st.commonParamsPreview = cp ? cp.slice(0, 120) : null;
  } catch (e) { st.commonParamsOk = false; S.lastErr.commonParams = '' + e; }
  st.ready = !!(st.tinyReady && st.shieldClassInit && st.shieldInstances > 0);
  return st;
}

function javaWarming() {
  return typeof Java === 'undefined' || !Java.available;
}

rpc.exports = {
  sign: function (method, url, bodyB64) {
    if (javaWarming()) throw new Error('Java VM 尚未就绪');
    var result = null, err = null;
    Java.perform(function () {
      try {
        ensureHooks(true);
        result = doSign(method, url, bodyB64 || '');
      } catch (e) {
        err = '' + e + '\n' + (e && e.$stack ? e.$stack : '');
      }
    });
    if (err) throw new Error(err);
    return result;
  },
  status: function () {
    if (javaWarming()) return { ready: false, warming: true };
    var st = null, err = null;
    Java.perform(function () {
      try { st = computeStatus(); } catch (e) { err = '' + e; }
    });
    if (err) return { ready: false, fatal: err, errors: S.lastErr };
    if (!st) return { ready: false, warming: true };  // VM 未起，perform 被排队
    return st;
  },
  debugurls: function () {
    return S.recentUrls.slice();
  },
  debugsample: function () {
    return { url: S.sampleUrl, headers: S.sampleHeaders };
  },
  debugresp: function () {
    return S.recentResp.slice();
  },
  rotateshield: function (xyterstr) {
    if (javaWarming()) throw new Error('Java VM 尚未就绪');
    var ok = false, err = null;
    Java.perform(function () {
      try { ok = rotateShield(xyterstr); } catch (e) { err = '' + e; }
    });
    if (err) throw new Error(err);
    return ok;
  },
  loginparams: function () {
    if (javaWarming()) throw new Error('Java VM 尚未就绪');
    var out = null, err = null;
    Java.perform(function () {
      try { out = getLoginParams(); } catch (e) { err = '' + e + '\n' + (e && e.stack ? e.stack : ''); }
    });
    if (err) throw new Error(err);
    return out;
  }
};

log('sign.js 已加载');
