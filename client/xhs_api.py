#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""小红书 App 签名 API 客户端。

签名（x-mini-*、shield、xy-platform-info、x-legacy-*、xy-common-params）由模拟器里
运行的 com.xingin.xhs 通过 frida RPC 实时计算；本脚本负责拼 URL、发 HTTP、解析 JSON。

用法：
    python xhs_api.py search "咖啡" [--page 1]
    python xhs_api.py note <note_id>
    python xhs_api.py login --zone 1 --phone <手机号> --password <明文>
    python xhs_api.py homefeed
    python xhs_api.py basic           # 未登录降级首页（当前唯一无风控门的链路）
    python xhs_api.py status          # 只看签名组件就绪状态
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse

import frida
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SIGN_JS = os.path.join(HERE, 'sign.js')
SESSION_JSON = os.path.join(HERE, 'session.json')
HEADER_TEMPLATE_JSON = os.path.join(HERE, 'header-template.json')
HOST = 'https://edith.xiaohongshu.com'

_SDK = os.environ.get('ANDROID_SDK_ROOT', '/opt/homebrew/share/android-commandlinetools')
ADB = os.path.join(_SDK, 'platform-tools', 'adb')
if not os.path.exists(ADB):
    ADB = 'adb'

# 两套目标：emu = 模拟器 + 隐藏版 frida-server；real = 真机 + 重打包 gadget
TARGETS = {
    'emu': {
        'serial': 'emulator-5554',       # 显式指定（真机同时连着，不带 -s 会报多设备）
        'pkg': 'com.xingin.xhs',
        'frida_host': os.environ.get('XHS_FRIDA_HOST', '127.0.0.1:44444'),
        'gadget': False,
    },
    'real': {
        'serial': '101114e',               # 小米 kunzite，Android 15
        'pkg': 'com.xingin.xhsre',         # 重打包包名（与官方包共存）
        'frida_host': os.environ.get('XHS_GADGET_HOST', '127.0.0.1:27043'),
        'gadget': True,                    # 进程内 gadget，不能 spawn，只能启动后 attach
    },
}
TARGET = os.environ.get('XHS_TARGET', 'emu')


def log(msg):
    print(f'[xhs] {msg}', file=sys.stderr)


class XhsClient:
    def __init__(self, spawn=True, ready_timeout=120, target=None):
        self.cfg = TARGETS[target or TARGET]
        self.pkg = self.cfg['pkg']
        self.device = self._get_device()
        self.pid = None
        self.spawned = False
        self.script = None
        self.session = None
        self.session_id = None
        self._load_session()
        self._load_header_fallback()
        self._launch(spawn and not self.cfg['gadget'])
        self._load_script()
        if self.spawned:
            self.device.resume(self.pid)
            log('App 已 resume')
        self._wait_ready(ready_timeout)
        self.http = requests.Session()

    # ---------- 目标相关的底层 ----------
    def _adb(self, *args):
        cmd = [ADB]
        if self.cfg['serial']:
            cmd += ['-s', self.cfg['serial']]
        return subprocess.run(cmd + list(args), capture_output=True, text=True,
                              timeout=30).stdout.strip()

    def _get_device(self):
        host = self.cfg['frida_host']
        if host == 'usb':
            return frida.get_usb_device()
        port = host.rsplit(':', 1)[-1]
        fwd = [ADB]
        if self.cfg['serial']:
            fwd += ['-s', self.cfg['serial']]
        subprocess.run(fwd + ['forward', f'tcp:{port}', f'tcp:{port}'],
                       capture_output=True, timeout=15)
        return frida.get_device_manager().add_remote_device(host)

    def _xhs_pid(self):
        """主进程会 prctl 改名（frida 枚举里显示 'rednote'），按 cmdline 精确取 pid。"""
        out = self._adb('shell', 'pidof', self.pkg).split()
        return int(out[0]) if out else None

    def _load_script(self):
        self.script = self.session.create_script(
            open(SIGN_JS, encoding='utf-8').read())
        self.script.on('message', self._on_message)
        self.script.load()

    def _reattach(self):
        """进程死后（看门狗/自重启），重新拉起并 attach，重载脚本等到就绪。"""
        log('会话已断开，尝试重新 attach...')
        for _ in range(30):
            try:
                if self.cfg['gadget']:
                    self._launch_gadget()
                else:
                    pid = self._xhs_pid()
                    if pid is None:
                        time.sleep(1)
                        continue
                    self.pid = pid
                    self.session = self.device.attach(pid)
                self._load_script()
                log(f'重新 attach 成功 pid={self.pid}，等待就绪')
                for _ in range(30):
                    st = self.script.exports_sync.status() or {}
                    if st.get('ready'):
                        log('重 attach 后就绪')
                        return True
                    time.sleep(1)
            except Exception as e:
                log(f'attach 异常：{e}')
                time.sleep(1)
        return False

    # ---------- 启动 / attach ----------
    def _launch_gadget(self):
        """真机 gadget 形态：monkey 拉起 App，gadget 在 attachBaseContext 里
        on_load=wait 等 frida 连接；连上 remote device 后 attach 到它报告的进程。"""
        self._adb('shell', 'monkey', '-p', self.pkg, '-c',
                  'android.intent.category.LAUNCHER', '1')
        for _ in range(60):
            try:
                self.device = self._get_device()
                procs = self.device.enumerate_processes()
                if procs:
                    self.pid = procs[0].pid
                    self.session = self.device.attach(self.pid)
                    log(f'gadget attach 成功 pid={self.pid}')
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError('gadget 一直不可连接')

    def _launch(self, spawn):
        if self.cfg['gadget']:
            self._launch_gadget()
            return
        if spawn:
            try:
                # 防止上一个实例残留导致多进程并存
                self._adb('shell', 'am', 'force-stop', self.pkg)
                time.sleep(1)
                self.pid = self.device.spawn([self.pkg])
                self.spawned = True
                self.session = self.device.attach(self.pid)
                log(f'spawn 成功 pid={self.pid}')
                return
            except Exception as e:
                log(f'spawn 失败（{e}），退化到 monkey 启动 + attach')
                self.pid = None
                self.spawned = False
        self._adb('shell', 'monkey', '-p', self.pkg, '-c',
                  'android.intent.category.LAUNCHER', '1')
        for _ in range(60):
            pid = self._xhs_pid()
            if pid is not None:
                try:
                    self.pid = pid
                    self.session = self.device.attach(pid)
                    log(f'attach 成功 pid={pid}')
                    return
                except Exception as e:
                    log(f'attach 失败（{e}），重试')
            time.sleep(1)
        raise RuntimeError('App 进程一直没起来')

    def _on_message(self, msg, data):
        # frida 17 的 Java 桥按需加载协议：脚本发 frida:load-bridge，宿主回桥源码
        payload = msg.get('payload')
        if msg.get('type') == 'send' and isinstance(payload, dict) \
                and payload.get('type') == 'frida:load-bridge':
            name = payload['name'].lower()
            path = os.path.join(HERE, f'{name}-bridge.js')
            self.script.post({'type': 'frida:bridge-loaded',
                              'filename': f'{name}-bridge.js',
                              'source': open(path, encoding='utf-8').read()})
            return
        if msg.get('type') == 'send':
            log(f"js: {payload}")
        elif msg.get('type') == 'error':
            log(f"js error: {msg.get('description')}\n{msg.get('stack', '')}")

    # ---------- 等待签名组件就绪 ----------
    def _wait_ready(self, timeout):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                st = self.script.exports_sync.status() or {'warming': True}
            except Exception as e:
                log(f'status 调用失败（{type(e).__name__}: {e}）')
                if not self._reattach():
                    break
                continue
            last = st
            if st.get('ready'):
                log('签名组件就绪：'
                    f"tiny={st.get('tinyReady')} "
                    f"shield(class={st.get('shieldClassInit')}, inst={st.get('shieldInstances')}) "
                    f"sample={st.get('sampleCaptured')} "
                    f"commonParams={st.get('commonParamsOk')}")
                return
            time.sleep(2)
        raise RuntimeError('等待签名组件就绪超时，最后状态：\n'
                           + json.dumps(last, ensure_ascii=False, indent=2))

    # ---------- 签名 ----------
    _FALLBACK_SKIP = {
        'host', 'connection', 'content-length', 'content-type', 'accept-encoding',
        'transfer-encoding', 'shield', 'xy-platform-info', 'xy-common-params',
        'x-mini-mua', 'x-mini-s1', 'x-mini-sig', 'x-mini-gid',
        'x-legacy-did', 'x-legacy-fid', 'x-legacy-sid',
        'x-b3-traceid', 'x-b3-spanid', 'x-b3-sampled', 'x-xray-traceid',
        'traceparent', 'x-trace-id', 'cookie',
    }

    def _load_header_fallback(self):
        """JS 侧还没抓到真实样本时，用落盘的样本头兜底（User-Agent/Referer 等）。"""
        self._header_fallback = []
        try:
            self._header_fallback = json.load(
                open(HEADER_TEMPLATE_JSON, encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def sign(self, method, url, body=b''):
        body_b64 = base64.b64encode(body).decode() if body else ''
        res = self.script.exports_sync.sign(method, url, body_b64)
        headers = res['headers']
        if not res.get('meta', {}).get('template'):
            have = {k.lower() for k in headers}
            for n, v in self._header_fallback:
                if n.lower() not in self._FALLBACK_SKIP and n.lower() not in have:
                    headers[n] = v
        # 登录态：用保存的 session 覆盖 x-legacy-sid
        # （tiny/shield 的签名摘要不包含该头，签后覆盖安全）
        if self.session_id:
            headers['x-legacy-sid'] = self.session_id
        return headers

    # ---------- 登录态持久化 ----------
    def _load_session(self):
        try:
            data = json.load(open(SESSION_JSON, encoding='utf-8'))
            self.session_id = data.get('session')
            if self.session_id:
                log(f"已加载登录态（userid={data.get('userid')}, "
                    f"session={self.session_id[:12]}...）")
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_session(self, data):
        json.dump(data, open(SESSION_JSON, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=2)
        log(f'登录态已写入 {SESSION_JSON}')

    # ---------- HTTP ----------
    def _send(self, method, url, body=b'', content_type=None, _retries=2):
        last_exc = None
        for attempt in range(_retries + 1):
            try:
                # requests 可能对 URL 做规范化，签名必须以最终发出的 URL 为准
                pre = self.http.prepare_request(
                    requests.Request(method, url, data=body if body else None))
                if content_type:
                    pre.headers['Content-Type'] = content_type
                headers = self.sign(method, pre.url, body)
                pre.headers.update(headers)
                if content_type:  # sign 模板头可能带 content-type，强制保持我们的
                    pre.headers['Content-Type'] = content_type
                r = self.http.send(pre, timeout=20)
            except Exception as e:
                # 进程被看门狗杀掉 → 重 attach 后重试
                log(f'请求失败（{type(e).__name__}: {str(e)[:80]}），尝试重 attach')
                last_exc = e
                if attempt < _retries and self._reattach():
                    continue
                raise
            # 406 + xy-ter-str = 服务端要求轮换 shield hmac 密钥（libxyass §7）
            if r.status_code == 406 and 'xy-ter-str' in r.headers and attempt < _retries:
                log('收到 406 + xy-ter-str，轮换 shield 密钥后重试')
                try:
                    self.script.exports_sync.rotateshield(r.headers['xy-ter-str'])
                except Exception as e:
                    log(f'轮换失败（{e}）')
                    if not self._reattach():
                        raise
                continue
            return r
        raise last_exc

    def get(self, path, params=None, _retries=2):
        if params:
            qs = urllib.parse.urlencode(params)
            url = f'{HOST}{path}?{qs}'
        else:
            url = f'{HOST}{path}'
        return self._send('GET', url, _retries=_retries)

    def post_form(self, path, form, _retries=2):
        body = urllib.parse.urlencode(form).encode()
        return self._send('POST', f'{HOST}{path}', body=body,
                          content_type='application/x-www-form-urlencoded; charset=utf-8',
                          _retries=_retries)

    # ---------- 登录 ----------
    def login_password(self, zone, phone, password):
        """密码登录。password 为明文，按 App 逻辑 MD5(UTF-8).hex 小写后提交。
        设备参数（android_id/oaid/gaid 等）借 App 的 fr.b0/is.a0 现算。"""
        pw_md5 = hashlib.md5(password.encode('utf-8')).hexdigest()
        form = {'password': pw_md5, 'zone': zone, 'phone': phone}
        try:
            dev_params = self.script.exports_sync.loginparams()
            log(f'登录设备参数 {len(dev_params)} 项：'
                + ', '.join(f'{k}={str(v)[:12]}' for k, v in list(dev_params.items())[:6]))
            form.update({k: ('' if v is None else str(v)) for k, v in dev_params.items()})
        except Exception as e:
            log(f'取登录设备参数失败（{e}），只带基础三项')
        r = self.post_form('/api/sns/v4/user/login/password', form)
        j = r.json() if r.text else {}
        data = j.get('data') or {}
        if j.get('success') and data.get('session'):
            self.session_id = data['session']
            self._save_session({
                'session': data.get('session'),
                'userid': data.get('userid') or data.get('user_id'),
                'secure_session': data.get('secure_session'),
                'phone': phone, 'zone': zone,
                'saved_at': int(time.time()),
            })
        return r

    # ---------- API ----------
    def search_notes(self, keyword, page=1, page_size=20):
        params = {
            'keyword': keyword,
            'page': page,
            'page_size': page_size,
            'sort': 'general',
            'source': 'explore',
            'search_tab': 'notes',
        }
        return self.get('/api/sns/v10/search/notes', params)

    def get_note(self, note_id, xsec_token=''):
        params = {
            'note_id': note_id,
            'page': 1,
            'has_ads_tag': 0,
            'num': 5,
            'fetch_mode': 1,
            'source': 'explore',
        }
        return self.get('/api/sns/v1/note/imagefeed', params)

    def homefeed(self):
        params = {
            'oid': 'homefeed_recommend',
            'cursor_score': '',
            'note_index': 0,
            'refresh_type': 1,
            'launch_scenario': 1,
        }
        return self.get('/api/sns/v6/homefeed', params)

    def basic_homefeed(self):
        """未登录降级接口（App 未登录时首页实际走的就是它）。"""
        params = {
            'oid': 'homefeed_recommend',
            'cursor_score': '',
            'note_index': 0,
            'refresh_type': 1,
        }
        return self.get('/api/sns/v1/note/basic/homefeed', params)


def dump_resp(r, limit=600):
    print(f'HTTP {r.status_code}')
    try:
        j = r.json()
        print(json.dumps(j, ensure_ascii=False)[:limit])
        return j
    except Exception:
        print(r.text[:limit])
        return None


def main():
    ap = argparse.ArgumentParser(description='小红书签名 API 客户端')
    ap.add_argument('--no-spawn', action='store_true', help='不 spawn，用 monkey 启动后 attach')
    ap.add_argument('--target', choices=['emu', 'real'], default=None,
                    help='emu=模拟器+frida-server（默认）；real=真机101114e+gadget 重打包包')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('search'); p.add_argument('keyword'); p.add_argument('--page', type=int, default=1)
    p = sub.add_parser('note'); p.add_argument('note_id'); p.add_argument('--xsec-token', default='')
    p = sub.add_parser('login'); p.add_argument('--zone', default='1')
    p.add_argument('--phone', required=True); p.add_argument('--password', required=True)
    sub.add_parser('homefeed')
    sub.add_parser('basic')
    sub.add_parser('status')
    args = ap.parse_args()

    client = XhsClient(spawn=not args.no_spawn, target=args.target)

    if args.cmd == 'status':
        print(json.dumps(client.script.exports_sync.status(),
                         ensure_ascii=False, indent=2))
        return

    if args.cmd == 'login':
        r = client.login_password(args.zone, args.phone, args.password)
        j = dump_resp(r, limit=1200)
        if j:
            print('success =', j.get('success'), ' code =', j.get('code'),
                  ' msg =', j.get('msg'))
            data = j.get('data') or {}
            print('userid =', data.get('userid') or data.get('user_id'))
            sess = data.get('session') or ''
            print('session =', sess[:12] + '...' if sess else None)
        return

    if args.cmd == 'search':
        r = client.search_notes(args.keyword, page=args.page)
        j = dump_resp(r)
        if j:
            print('success =', j.get('success'), ' code =', j.get('code'),
                  ' msg =', j.get('msg'))
            items = j.get('data', {}).get('items') or []
            print(f'items: {len(items)}')
            for it in items[:5]:
                card = it.get('note_card', {})
                print(' -', it.get('id'), '|', card.get('display_title'))
    elif args.cmd == 'note':
        r = client.get_note(args.note_id, args.xsec_token)
        j = dump_resp(r)
        if j:
            print('success =', j.get('success'), ' code =', j.get('code'),
                  ' msg =', j.get('msg'))
            items = j.get('data', {}).get('items') or []
            if items:
                note = items[0].get('note_card', {})
                print('标题:', note.get('title'))
                print('作者:', (note.get('user') or {}).get('nickname'))
                print('点赞:', (note.get('interact_info') or {}).get('liked_count'))
    elif args.cmd == 'homefeed':
        r = client.homefeed()
        j = dump_resp(r)
        if j:
            print('success =', j.get('success'), ' code =', j.get('code'),
                  ' msg =', j.get('msg'))
    elif args.cmd == 'basic':
        r = client.basic_homefeed()
        j = dump_resp(r)
        if j:
            print('success =', j.get('success'), ' code =', j.get('code'),
                  ' msg =', j.get('msg'))
            items = j.get('data') or []
            print(f'items: {len(items)}')
            for it in items[:5]:
                print(' -', it.get('id') or it.get('note_id'), '|',
                      (it.get('title') or it.get('display_title') or '')[:40])


if __name__ == '__main__':
    main()
