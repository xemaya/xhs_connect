#!/usr/bin/env python3
"""纯 adb 滚动收割：驱动 xhsre 搜索页滚动，响应由 mitmproxy 插件落盘。

前置：
  1. 手机全局代理指向 Mac（settings put global http_proxy <mac>:8082）
  2. mitmdump --listen-port 8082 -s mitm_harvest_addon.py 在跑
  3. xhsre 已原生登录（UI 登录，不要注入）

用法：python ui_scroll_harvest.py --keyword '伦敦 二手' --scrolls 40 --cap 500
"""
import argparse
import base64
import json
import os
import subprocess
import time

from xhs_api import XhsClient, ADB, TARGETS, log

HERE = os.path.dirname(os.path.abspath(__file__))
SERIAL = TARGETS['real']['serial']
PKG = TARGETS['real']['pkg']
HARVEST_JSONL = '/tmp/xhs_harvest.jsonl'


def adb(*args, timeout=30):
    return subprocess.run([ADB, '-s', SERIAL] + list(args),
                          capture_output=True, text=True, timeout=timeout).stdout.strip()


def tap(x, y):
    adb('shell', 'input', 'swipe', str(x), str(y), str(x + 4), str(y + 3), '130')


def focus():
    out = adb('shell', 'dumpsys', 'window')
    for line in out.splitlines():
        if 'mCurrentFocus' in line:
            return line.strip()
    return ''


def focus_ok():
    return PKG in focus()


def ensure_foreground():
    if focus_ok():
        return
    adb('shell', 'input', 'keyevent', '224')
    time.sleep(1)
    adb('shell', 'input', 'swipe', '500', '1800', '500', '600', '300')
    time.sleep(1)
    adb('shell', 'am', 'start', '-n', f'{PKG}/com.xingin.xhs.index.v2.IndexActivityV2')
    time.sleep(4)
    if not focus_ok():
        raise RuntimeError('焦点不在 xhsre：' + focus())


def parse_note_item(it):
    """v10/search/notes 的 item：{model_type:'note', note:{id,xsec_token,title,desc,...}}"""
    note = it.get('note') or it.get('note_card') or {}
    nid = note.get('note_id') or note.get('id') or it.get('id') or ''
    if not nid:
        return None
    user = note.get('user') or {}
    pub = ''
    for tag in note.get('corner_tag_info') or []:
        if tag.get('type') == 'publish_time':
            pub = tag.get('text') or ''
    ts = note.get('update_time') or ((note.get('timestamp') or 0) * 1000) or 0
    images = []
    for im in note.get('images_list') or []:
        u = im.get('url_size_large') or im.get('url') or ''
        if u:
            images.append(u)
    return {
        'note_id': nid,
        'xsec_token': note.get('xsec_token') or '',
        'title': note.get('title') or '',
        'desc': note.get('desc') or '',
        'type': note.get('type') or '',
        'liked_count': note.get('liked_count'),
        'comments_count': note.get('comments_count'),
        'shared_count': note.get('shared_count'),
        'collected_count': note.get('collected_count'),
        'publish_time_text': pub,
        'timestamp': ts,
        'time_iso': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts / 1000)) if ts else '',
        'user': user.get('nickname') or '',
        'user_id': user.get('user_id') or user.get('userid') or '',
        'red_id': user.get('red_id') or '',
        'images': images,
    }


def parse_harvest(path, since=0.0):
    """读 mitm 落盘的 JSONL，抽出搜索 items 和详情。"""
    items = {}
    details = {}
    if not os.path.exists(path):
        return items, details
    for line in open(path, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get('ts', 0) < since:
            continue
        url = rec.get('url', '')
        body = rec.get('body', '')
        try:
            j = json.loads(body)
        except Exception:
            continue
        if '/api/sns/v10/search/notes' in url or '/api/sns/v3/search/notes' in url:
            for it in ((j.get('data') or {}).get('items') or []):
                p = parse_note_item(it)
                if p:
                    items[p['note_id']] = p
        elif '/api/sns/v1/note/imagefeed' in url:
            data = j.get('data') or []
            if isinstance(data, list) and data:
                entry = data[0]
                notes = entry.get('note_list') or []
                if notes:
                    nid = notes[0].get('note_id') or notes[0].get('id')
                    if nid:
                        details[nid] = j
    return items, details


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keyword', required=True)
    ap.add_argument('--scrolls', type=int, default=40)
    ap.add_argument('--cap', type=int, default=500)
    ap.add_argument('--scroll-sleep', type=float, default=3.0)
    ap.add_argument('--out', default='')
    ap.add_argument('--skip-nav', action='store_true',
                    help='搜索页已开着且有结果，直接滚动')
    args = ap.parse_args()

    ts = time.strftime('%Y%m%d_%H%M%S')
    out = args.out or os.path.join(
        HERE, 'out', f"scroll_{args.keyword.replace(' ', '_')}_{ts}.jsonl")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    start_ts = time.time()

    ensure_foreground()
    if not args.skip_nav:
        if 'GlobalSearch' not in focus():
            tap(1000, 190)  # 放大镜
            time.sleep(3)
            if 'GlobalSearch' not in focus():
                raise RuntimeError('未进入搜索页：' + focus())
        # 先清空再输入（ADBKeyBoard 是插入式，避免关键词叠加）
        adb('shell', 'am', 'broadcast', '-a', 'ADB_CLEAR_TEXT')
        time.sleep(0.8)
        b64 = base64.b64encode(args.keyword.encode()).decode()
        adb('shell', 'am', 'broadcast', '-a', 'ADB_INPUT_B64', '--es', 'msg', b64)
        time.sleep(1.5)
        ensure_foreground()
        tap(988, 186)  # 搜索按钮
        log(f'已触发搜索：{args.keyword}')
        time.sleep(5)

    stall = 0
    last_n = 0
    for i in range(args.scrolls):
        if not focus_ok():
            log('焦点丢失，中止（已收数据照常落盘）')
            break
        adb('shell', 'input', 'swipe', '540', '2050', '540', '350', '600')
        time.sleep(args.scroll_sleep)
        items, _ = parse_harvest(HARVEST_JSONL, start_ts - 60)
        log(f'滚动 {i + 1}/{args.scrolls}：累计 {len(items)} 条')
        if len(items) >= args.cap:
            log('达到封顶')
            break
        if len(items) == last_n:
            stall += 1
            if stall >= 8:
                log('连续 8 屏无新内容，到底了')
                break
        else:
            stall = 0
        last_n = len(items)

    items, details = parse_harvest(HARVEST_JSONL, start_ts - 60)
    with open(out, 'w', encoding='utf-8') as f:
        for it in items.values():
            f.write(json.dumps(it, ensure_ascii=False) + '\n')
    log(f'完成：{len(items)} 条列表 + {len(details)} 条详情 → {out}')
    print(json.dumps({'count': len(items), 'details': len(details), 'out': out},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
