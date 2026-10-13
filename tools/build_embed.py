#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组装 xhsre 的 gadget 内嵌脚本（script-interaction 形态）。

组成：
  1. 生存 hooks（exit/_exit 睡死、abort 吞掉）——native 层，立即生效
  2. java-bridge.js 内嵌——frida 17 不内建 Java 桥；script 模式无主机应答，直接内联
  3. vm.perform 早期钩 Signature.hashCode——绕过 Java.perform 的类加载器延迟队列
    （完整性校验在启动 ~1.4s 时跑，等 Java.perform 就绪就来不及）
  4. sign.js 全部签名逻辑（用 var rpc={exports:{}} 垫片原样复用）
  5. TCP JSON 服务（端口 27044）——script 模式没有 listener，自己起服务

产物：decoded/lib/arm64-v8a/libfrida-gadget.script.so
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.expanduser('~/re-targets/xhs-out/client')
DECODED_LIB = os.path.join(HERE, 'decoded', 'lib', 'arm64-v8a')

HEADER = r'''
/* ===== xhsre gadget 内嵌脚本（自包含：生存 hooks + 签名 RPC 服务） ===== */
var RELOG = '/sdcard/Android/data/com.xingin.xhsre/files/re.log';
function rlog(m) {
  try { var f = new File(RELOG, 'a'); f.write(m + '\n'); f.close(); } catch (e) {}
}
try { new File(RELOG, 'w').close(); } catch (e) {}
rlog('standalone init start');

/* ---- 1. 自杀封堵（native，先于一切） ---- */
(function () {
  var seen = {};
  ['exit', '_exit', '_Exit'].forEach(function (name) {
    var addr = Module.findGlobalExportByName(name);
    if (!addr || seen[addr.toString()]) return;
    seen[addr.toString()] = 1;
    try {
      Interceptor.replace(addr, new NativeCallback(function (code) {
        rlog('拦截 ' + name + '(' + code + ')');
        Thread.sleep(24 * 3600);
      }, 'void', ['int']));
    } catch (e) { rlog('封堵 ' + name + ' 失败: ' + e); }
  });
  try {
    var ab = Module.findGlobalExportByName('abort');
    if (ab && !seen[ab.toString()]) {
      Interceptor.replace(ab, new NativeCallback(function () {
        rlog('吞掉 abort()（签名校验失败开放兜底）');
      }, 'void', []));
    }
  } catch (e) { rlog('封堵 abort 失败: ' + e); }
})();

/* ---- 2. 内嵌 Java 桥（紧随其后的文本即 java-bridge.js 原文） ---- */
'''

MIDDLE = r'''
Object.defineProperty(globalThis, 'Java', { value: bridge });
rlog('java bridge embedded, Java=' + (typeof Java));

/* ---- 3. 早期签名哈希欺骗：绕过 Java.perform 的 ClassLoader 延迟队列 ---- */
// frida 桥的 Java.perform 在 app ClassLoader 未就绪时排队等待，小红书启动 ~1.4s
// 就跑完整性校验（libxyass initializeNative 读签名哈希，不符则 abort），等不起。
// vm.perform 直接挂当前线程执行；Signature 是框架类，不依赖 app ClassLoader。
try {
  rlog('Java.available=' + Java.available + ' vm=' + (typeof Java.vm));
  rlog('准备 vm.perform...');
  Java.vm.perform(function () {
    rlog('vm.perform entered');
    try {
      var Sig = Java.use('android.content.pm.Signature');
      Sig.hashCode.implementation = function () { return -1083242518; };
      rlog('Signature.hashCode 早期钩 OK，自测=' + Sig.$new('AAAA').hashCode());
    } catch (e) { rlog('hashCode hook fail: ' + e); }
  });
  rlog('vm.perform returned');
} catch (e) { rlog('vm.perform fail: ' + e); }

/* ---- 4. sign.js 逻辑（含其 rpc.exports 注册块；frida 运行时自带 rpc 全局） ---- */
'''

SERVER = r'''
/* ---- 5. TCP JSON 服务（script 模式没有 listener，自给自足） ---- */
// 协议：每行一个 JSON。请求 {"id":N,"method":"sign","params":[...]}
// 响应 {"id":N,"result":...} 或 {"id":N,"error":"..."}
rlog('core 加载完，进 server 段');
try {
function u8encode(s) {
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
    else if (c >= 0xd800 && c < 0xdc00 && i + 1 < s.length) {
      var c2 = s.charCodeAt(++i);
      var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
  }
  return new Uint8Array(out).buffer;
}
function u8decode(buf) {
  var b = new Uint8Array(buf), s = '', i = 0;
  while (i < b.length) {
    var c = b[i];
    if (c < 0x80) { s += String.fromCharCode(c); i++; }
    else if (c < 0xe0) { s += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63)); i += 2; }
    else if (c < 0xf0) { s += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63)); i += 3; }
    else {
      var cp = ((c & 7) << 18) | ((b[i + 1] & 63) << 12) | ((b[i + 2] & 63) << 6) | (b[i + 3] & 63);
      cp -= 0x10000;
      s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 1023)); i += 4;
    }
  }
  return s;
}

// 串行队列：签名函数用了全局假 chain 状态，不能并发
var gQueue = Promise.resolve();
function dispatch(req) {
  var fn = rpc.exports[req.method];
  if (!fn) throw new Error('未知方法: ' + req.method);
  var ps = req.params || [];
  return fn.apply(null, ps);
}
function handleLine(line, conn) {
  var req;
  try { req = JSON.parse(line); } catch (e) { return writeJson(conn, { id: null, error: 'bad json' }); }
  gQueue = gQueue.then(function () {
    try {
      var result = dispatch(req);
      return writeJson(conn, { id: req.id, result: result });
    } catch (e) {
      return writeJson(conn, { id: req.id, error: '' + e });
    }
  });
}
function writeJson(conn, obj) {
  return conn.output.writeAll(u8encode(JSON.stringify(obj) + '\n')).catch(function (e) {
    rlog('写响应失败: ' + e);
  });
}
function readLoop(conn, state) {
  conn.input.read(65536).then(function (buf) {
    if (!buf || buf.byteLength === 0) { onConnClosed(conn); return; }
    state.text += u8decode(buf);
    var idx;
    while ((idx = state.text.indexOf('\n')) >= 0) {
      var line = state.text.slice(0, idx).trim();
      state.text = state.text.slice(idx + 1);
      if (line) handleLine(line, conn);
    }
    readLoop(conn, state);
  }).catch(function () { onConnClosed(conn); });
}
function onConnClosed(conn) {
  try { conn.close(); } catch (e) {}
  if (typeof gConn !== 'undefined' && gConn === conn) {
    gConn = null;
    rlog('宿主连接断开，重连');
    connectToHost(30);
  }
}
// 反向通道：script 主动连 Mac 宿主（经 adb reverse tcp:27045）。
// 连接常驻并全局持有防 GC；宿主先发请求、脚本回响应（行分隔 JSON）。
var gConn = null;
function connectToHost(n) {
  Socket.connect({ family: 'ipv4', host: '127.0.0.1', port: 27045 }).then(function (conn) {
    gConn = conn;
    rlog('已接入宿主签名服务');
    readLoop(conn, { text: '' });
  }).catch(function (e) {
    rlog('connect 宿主失败(' + e + ')，剩余重试 ' + n);
    if (n > 0) connectToHost(n - 1);
  });
}
connectToHost(30);

// 正向监听兜底（accept 在本环境疑似不派发，留着无害）
try {
  Socket.listen({ family: 'ipv4', port: 27044 }).then(function (listener) {
    rlog('签名服务监听 127.0.0.1:27044');
    function acceptLoop() {
      listener.accept().then(function (conn) {
        rlog('客户端连入(正向)');
        readLoop(conn, { text: '' });
        acceptLoop();
      }).catch(function (e) { rlog('accept 失败: ' + e); });
    }
    acceptLoop();
  }).catch(function (e) { rlog('监听失败: ' + e); });
} catch (e) { rlog('Socket.listen 异常: ' + e); }
} catch (e2) { rlog('server 段异常: ' + e2 + ' stack=' + (e2 && e2.stack)); }

rlog('standalone init done');
'''


def main():
    bridge = open(os.path.join(CLIENT, 'java-bridge.js'), encoding='utf-8').read()
    sign = open(os.path.join(CLIENT, 'sign.js'), encoding='utf-8').read()

    # 从 sign.js 里取 `var S = {` 到文件末尾（含 rpc.exports 注册块；definitions+注册即可，
    # 前面的 blockSuicide/Java 桥/Signature hook 段我们已在 HEADER/MIDDLE 用更强版本实现）
    start = sign.index('var S = {')
    core = sign[start:]

    out = (HEADER + bridge + MIDDLE
           + 'try {\n' + core + '\n} catch (e) { rlog("core 段异常: " + e + " stack=" + (e && e.stack)); }\n'
           + SERVER)
    dst = os.path.join(DECODED_LIB, 'libfrida-gadget.script.so')
    open(dst, 'w', encoding='utf-8').write(out)
    print('script bytes:', len(out), '->', dst)

    cfg = {"interaction": {"type": "script",
                           "path": "libfrida-gadget.script.so",
                           "on_change": "reload"}}
    with open(os.path.join(DECODED_LIB, 'libfrida-gadget.config.so'), 'w') as f:
        json.dump(cfg, f, indent=1)
    print('config written (script interaction)')


if __name__ == '__main__':
    main()
