#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真机全链路：login（设备内发）→ search → note，进程死掉就重启重试。"""
import base64
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, '/Users/huanghaibin/re-targets/xhs-out/client')
from xhs_api import XhsClient, ADB

SESSION_OUT = '/Users/huanghaibin/re-targets/xhs-out/client/session.json'


def sh(*args):
    return subprocess.run([ADB, '-s', '101114e', 'shell'] + list(args),
                          capture_output=True, timeout=15).stdout.decode().strip()


def restart_app():
    sh('am', 'force-stop', 'com.xingin.xhsre')
    time.sleep(1)
    sh('input', 'keyevent', 'KEYCODE_WAKEUP')
    sh('am', 'start', '-n', 'com.xingin.xhsre/com.xingin.xhs.index.v2.IndexActivityV2')


MODE = 'raw'  # appfetch=App 完整链 / raw=签名+裸发

def device_post(c, url, form):
    body = urllib.parse.urlencode(form).encode()
    b64 = base64.b64encode(body).decode()
    if MODE == 'appfetch':
        return c._rpc('fetch', 'POST', url, b64,
                      'application/x-www-form-urlencoded; charset=utf-8')
    res = c._rpc('sign', 'POST', url, b64)
    headers = [[k, str(v)] for k, v in res['headers'].items()]
    headers.append(['Content-Type', 'application/x-www-form-urlencoded; charset=utf-8'])
    return c._rpc('rawfetch', url, headers, b64)


def device_get(c, url):
    if MODE == 'appfetch':
        return c._rpc('fetch', 'GET', url, '', '')
    res = c._rpc('sign', 'GET', url, '')
    headers = [[k, str(v)] for k, v in res['headers'].items()]
    return c._rpc('rawfetch', url, headers, '')


def attempt(n):
    restart_app()
    c = XhsClient(target='real', spawn=False, ready_timeout=45)

    # 1) 登录（设备内发，手机 IP 不过 300012）
    pw_md5 = hashlib.md5('qq123456'.encode()).hexdigest()
    form = {'password': pw_md5, 'zone': '1', 'phone': '2895874976'}
    dev = c._rpc('loginparams')
    form.update({k: ('' if v is None else str(v)) for k, v in dev.items()})
    r = device_post(c, 'https://edith.xiaohongshu.com/api/sns/v4/user/login/password', form)
    print(f'[login] HTTP {r["code"]}', flush=True)
    body = r.get('body') or ''
    print(body[:300], flush=True)
    j = json.loads(body) if body else {}
    data = j.get('data') or {}
    if not (j.get('success') and data.get('session')):
        return False
    sess = {
        'session': data.get('session'),
        'userid': data.get('userid') or data.get('user_id'),
        'secure_session': data.get('secure_session'),
        'saved_at': int(time.time()),
    }
    json.dump(sess, open(SESSION_OUT, 'w'), ensure_ascii=False, indent=2)
    c.session_id = sess['session']
    print(f'[login] OK userid={sess["userid"]}', flush=True)

    # 2) 搜索（全参数）
    params = {
        'keyword': '咖啡', 'filters': '', 'sort': 'general',
        'page': 1, 'page_size': 20, 'source': 'explore',
        'search_id': uuid.uuid4().hex, 'session_id': uuid.uuid4().hex,
        'api_extra': '', 'page_pos': 0, 'ext_params': '', 'pin_note_id': '',
        'allow_rewrite': 1, 'geo': '', 'loaded_ad': '',
        'query_extra_info': '', 'rec_extra_params': '', 'scene': 'search',
        'is_optimize': 0, 'location_permission': 0, 'device_level': 2,
        'refresh_type': 1, 'exp_infos': '', 'feed_oaid': '',
        'known_signal': '', 'ai_mode': 0, 'search_tab': 'notes',
    }
    url = 'https://edith.xiaohongshu.com/api/sns/v10/search/notes?' + urllib.parse.urlencode(params)
    r = device_get(c, url)
    print(f'[search] HTTP {r["code"]}', flush=True)
    j = json.loads(r.get('body') or '{}')
    items = (j.get('data') or {}).get('items') or []
    print(f'[search] success={j.get("success")} code={j.get("code")} items={len(items)}', flush=True)
    note_id = None
    for it in items:
        if it.get('note_card'):
            note_id = it.get('id')
            print('  -', note_id, '|', (it.get('note_card') or {}).get('display_title'), flush=True)
    if not note_id:
        return False

    # 3) 笔记详情
    nparams = {'note_id': note_id, 'page': 1, 'has_ads_tag': 0, 'num': 5,
               'fetch_mode': 1, 'source': 'explore'}
    nurl = 'https://edith.xiaohongshu.com/api/sns/v1/note/imagefeed?' + urllib.parse.urlencode(nparams)
    r = device_get(c, nurl)
    print(f'[note] HTTP {r["code"]}', flush=True)
    j = json.loads(r.get('body') or '{}')
    items = (j.get('data') or {}).get('items') or []
    print(f'[note] success={j.get("success")} code={j.get("code")} items={len(items)}', flush=True)
    if items:
        nc = items[0].get('note_card') or {}
        print('  标题:', nc.get('title'), flush=True)
        print('  作者:', (nc.get('user') or {}).get('nickname'), flush=True)
        return True
    return False


for i in range(5):
    try:
        print(f'===== 第 {i+1} 次尝试 =====', flush=True)
        if attempt(i + 1):
            print('全链路完成！', flush=True)
            break
    except Exception as e:
        print(f'第 {i+1} 次失败: {type(e).__name__}: {e}', flush=True)
        time.sleep(3)
