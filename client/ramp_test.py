#!/usr/bin/env python3
"""爬坡实测：逐级提速跑详情，定位分钟级速率触发线（§14.6 待办）。

每级 20 条固定间隔，级间停 5 分钟；出现 300011 / -100 / 461 或进度停滞立即熔断。
用法：python ramp_test.py --list out/伦敦二手_滚动收割合并.jsonl
"""
import argparse
import json
import os
import subprocess
import sys
import time

from xhs_api import ADB, TARGETS, log

T = TARGETS['huawei']
SERIAL = T['serial']
PKG = T['pkg']
HARVEST_JSONL = '/tmp/xhs_harvest.jsonl'
REMOTE_Q = f'/sdcard/Android/data/{PKG}/files/q_ramp.txt'
LOCAL_Q = '/tmp/q_ramp.txt'

LEVELS = [
    ('L1 5条/分', 12000),
    ('L2 8条/分', 7500),
    ('L3 12条/分', 5000),
    ('L4 16条/分', 3750),
]
PER_LEVEL = 20
PAUSE = 300          # 级间停顿秒
STALL_LIMIT = 150    # 秒无进展判停滞


def adb(*args, timeout=60):
    return subprocess.run([ADB, '-s', SERIAL] + list(args),
                          capture_output=True, text=True, timeout=timeout).stdout.strip()


def captured():
    """返回 {note_id: code_in_body}，只看 imagefeed。"""
    out = {}
    if not os.path.exists(HARVEST_JSONL):
        return out
    for line in open(HARVEST_JSONL, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        u = rec.get('url', '')
        if 'imagefeed' not in u:
            continue
        q = u.split('note_id=')
        if len(q) < 2:
            continue
        nid = q[1].split('&')[0]
        body = rec.get('body', '')
        mark = 'ok'
        try:
            bcode = json.loads(body).get('code', 0)
        except Exception:
            bcode = 0
        if bcode in (-100, 300011):
            mark = f'BAD({bcode})'
        elif rec.get('code') != 200:
            mark = f"HTTP{rec.get('code')}"
        out[nid] = mark
    return out


def wake_app():
    adb('shell', 'input', 'keyevent', '224')
    time.sleep(1)
    adb('shell', 'am', 'start', '-n', f'{PKG}/com.xingin.xhs.index.v2.IndexActivityV2')
    time.sleep(5)


def fire(interval):
    adb('shell', 'am', 'broadcast', '-a', 'com.xhsre.driver.FETCH_DETAILS',
        '-p', PKG, '-f', '0x00000020',
        '--es', 'path', REMOTE_Q, '--el', 'interval', str(interval),
        timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--list', required=True)
    ap.add_argument('--start-level', type=int, default=0)
    args = ap.parse_args()

    want = [json.loads(l)['note_id'] for l in open(args.list, encoding='utf-8')]
    log(f'目标池 {len(want)} 条（取未收过的）')

    for li, (name, interval) in enumerate(LEVELS):
        if li < args.start_level:
            continue
        got = captured()
        remain = [i for i in want if i not in got]
        log(f'=== {name}（间隔 {interval}ms）：已收 {len(got)}，本池剩 {len(remain)} ===')
        if len(remain) < PER_LEVEL:
            log('剩余不足一级，爬坡结束')
            break
        batch = remain[:PER_LEVEL]
        open(LOCAL_Q, 'w').write('\n'.join(batch))
        adb('push', LOCAL_Q, REMOTE_Q)
        wake_app()
        log(f'点火 {len(batch)} 条 @{interval}ms')
        fire(interval)

        t0 = time.time()
        seen_batch = {}
        stalled = False
        while time.time() - t0 < PER_LEVEL * interval / 1000 + STALL_LIMIT:
            time.sleep(15)
            cur = captured()
            seen_batch = {i: cur[i] for i in batch if i in cur}
            bad = {k: v for k, v in seen_batch.items() if v != 'ok'}
            if bad:
                log(f'!!! 异常信号：{bad} —— 爬坡熔断')
                sys.exit(2)
            if len(seen_batch) >= len(batch):
                break
            # 停滞检测：预计时间过半仍 0 收获
            if time.time() - t0 > STALL_LIMIT and not seen_batch:
                log('!!! 本批零收获且超时（进程被杀？）—— 爬坡熔断')
                stalled = True
                break
        log(f'{name} 收齐 {len(seen_batch)}/{len(batch)}，用时 {int(time.time()-t0)}s')
        if stalled:
            sys.exit(2)
        if li < len(LEVELS) - 1:
            log(f'级间冷却 {PAUSE}s')
            time.sleep(PAUSE)

    log('爬坡完成，未触发异常')


if __name__ == '__main__':
    main()
