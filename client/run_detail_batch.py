#!/usr/bin/env python3
"""详情批量收割编排器：进程会被风控杀，按"剩余队列重推+重播"循环直到收齐。

用法：python run_detail_batch.py --list out/伦敦二手_滚动收割合并.jsonl [--interval 3000]
"""
import argparse
import json
import os
import subprocess
import time

from xhs_api import ADB, TARGETS, log

SERIAL = TARGETS['real']['serial']
PKG = TARGETS['real']['pkg']
HARVEST_JSONL = '/tmp/xhs_harvest.jsonl'
REMOTE_Q = f'/sdcard/Android/data/{PKG}/files/q_batch.txt'
LOCAL_Q = '/tmp/q_batch.txt'


def adb(*args, timeout=30):
    return subprocess.run([ADB, '-s', SERIAL] + list(args),
                          capture_output=True, text=True, timeout=timeout).stdout.strip()


def captured_ids():
    ids = set()
    if not os.path.exists(HARVEST_JSONL):
        return ids
    for line in open(HARVEST_JSONL, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        u = rec.get('url', '')
        if 'imagefeed' not in u:
            continue
        q = u.split('note_id=')
        if len(q) > 1:
            ids.add(q[1].split('&')[0])
    return ids


def wake_and_launch():
    adb('shell', 'input', 'keyevent', '224')
    time.sleep(1)
    adb('shell', 'input', 'swipe', '500', '1800', '500', '600', '300')
    time.sleep(1)
    adb('shell', 'am', 'start', '-n', f'{PKG}/com.xingin.xhs.index.v2.IndexActivityV2')
    time.sleep(6)


def fire(interval):
    adb('shell', 'am', 'broadcast', '-a', 'com.xhsre.driver.FETCH_DETAILS',
        '-p', PKG, '-f', '0x00000020',
        '--es', 'path', REMOTE_Q, '--el', 'interval', str(interval),
        timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--list', required=True)
    ap.add_argument('--interval', type=int, default=3000)
    ap.add_argument('--max-rounds', type=int, default=30)
    args = ap.parse_args()

    want = [json.loads(l)['note_id'] for l in open(args.list, encoding='utf-8')]
    log(f'目标 {len(want)} 条，interval={args.interval}ms')

    for rd in range(1, args.max_rounds + 1):
        done = captured_ids()
        remain = [i for i in want if i not in done]
        log(f'第 {rd} 轮：已收 {len(done)}/{len(want)}，剩余 {len(remain)}')
        if not remain:
            break
        open(LOCAL_Q, 'w').write('\n'.join(remain))
        adb('push', LOCAL_Q, REMOTE_Q)
        wake_and_launch()
        fire(args.interval)
        # 等本轮跑完或停滞
        est = len(remain) * (args.interval / 1000 + 0.6)
        t0 = time.time()
        last_n = len(done)
        stall = 0
        while time.time() - t0 < est + 180:
            time.sleep(20)
            n = len(captured_ids())
            if n == last_n:
                stall += 1
                if stall >= 5:   # 100s 无进展 → 可能进程被杀，下一轮重推
                    log('进度停滞，进入下一轮')
                    break
            else:
                stall = 0
                last_n = n
            if len(captured_ids() & set(want)) >= len(want):
                break

    done = captured_ids() & set(want)
    log(f'完成：{len(done)}/{len(want)}')
    print(json.dumps({'captured': len(done), 'total': len(want)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
