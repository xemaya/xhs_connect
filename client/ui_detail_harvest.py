#!/usr/bin/env python3
"""详情批量收割：在搜索结果页逐个点进笔记详情，imagefeed 由 mitm 插件落盘。

用法：python ui_detail_harvest.py [--count 328] [--per-col 8]
前置：搜索页已打开且有结果；mitmdump 收割模式在跑。
"""
import argparse
import base64
import json
import os
import subprocess
import time

from xhs_api import ADB, TARGETS, log

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


def research(keyword):
    """回搜索页：首页 → 放大镜 → 清空输入 → 关键词 → 搜索"""
    adb('shell', 'am', 'start', '-n', f'{PKG}/com.xingin.xhs.index.v2.IndexActivityV2')
    time.sleep(3)
    tap(1000, 190)
    time.sleep(3)
    if 'GlobalSearch' not in focus():
        return False
    adb('shell', 'am', 'broadcast', '-a', 'ADB_CLEAR_TEXT')
    time.sleep(0.8)
    b64 = base64.b64encode(keyword.encode()).decode()
    adb('shell', 'am', 'broadcast', '-a', 'ADB_INPUT_B64', '--es', 'msg', b64)
    time.sleep(1.5)
    tap(988, 186)
    time.sleep(5)
    return 'GlobalSearch' in focus()


def count_details():
    n = set()
    if not os.path.exists(HARVEST_JSONL):
        return 0
    for line in open(HARVEST_JSONL, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if '/api/sns/v1/note/imagefeed' in rec.get('url', ''):
            # note_id 在 query 里
            q = rec['url'].split('note_id=')
            if len(q) > 1:
                n.add(q[1].split('&')[0])
    return len(n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--count', type=int, default=350, help='目标详情条数')
    ap.add_argument('--keyword', default='伦敦 二手', help='掉回首页时重搜用')
    ap.add_argument('--scroll-every', type=int, default=6, help='每点几张卡滚一小段')
    ap.add_argument('--settle', type=float, default=2.2, help='进详情页后等待秒数')
    args = ap.parse_args()

    if 'GlobalSearch' not in focus():
        raise SystemExit('请先停在搜索结果页再跑：' + focus())

    n0 = count_details()
    log(f'起点详情数 {n0}，目标 {args.count}')
    col = 0
    fail_streak = 0
    i = 0
    while count_details() - n0 < args.count and fail_streak < 20:
        i += 1
        x = 270 if col == 0 else 810
        tap(x, 1200)
        col ^= 1
        t0 = time.time()
        ok = False
        while time.time() - t0 < 5:
            f = focus()
            # 图文是 NoteDetailActivity，视频是别的 activity —— 离开搜索页即算进入
            if PKG in f and 'GlobalSearch' not in f:
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            fail_streak += 1
            log(f'第 {i} 次未进入详情页（{fail_streak}），滚动一下')
            adb('shell', 'input', 'swipe', '540', '1500', '540', '900', '400')
            time.sleep(1.5)
            continue
        fail_streak = 0
        time.sleep(args.settle)
        adb('shell', 'input', 'keyevent', '4')   # 返回列表
        time.sleep(1.2)
        if 'GlobalSearch' not in focus():
            log('返回后不在搜索页（' + focus() + '），再按一次返回')
            adb('shell', 'input', 'keyevent', '4')
            time.sleep(1.5)
            if 'GlobalSearch' not in focus():
                log('仍不在搜索页，重搜恢复')
                if not research(args.keyword):
                    log('重搜失败，中止')
                    break
        if i % args.scroll_every == 0:
            adb('shell', 'input', 'swipe', '540', '1500', '540', '900', '400')
            time.sleep(1.5)
        if i % 20 == 0:
            log(f'已点 {i} 次，详情累计 {count_details() - n0}')

    log(f'完成：本轮新增详情 {count_details() - n0} 条')
    print(json.dumps({'new_details': count_details() - n0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
