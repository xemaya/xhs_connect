#!/usr/bin/env python3
"""详情批量收割编排器：进程会被风控杀，按"剩余队列重推+重播"循环直到收齐。

用法：python run_detail_batch.py --list out/伦敦二手_滚动收割合并.jsonl [--interval 3000]
"""
import argparse
import json
import os
import random
import subprocess
import time

from xhs_api import ADB, TARGETS, log

SERIAL = TARGETS['real']['serial']
PKG = TARGETS['real']['pkg']
HARVEST_JSONL = '/tmp/xhs_harvest.jsonl'
REMOTE_Q = f'/sdcard/Android/data/{PKG}/files/q_batch.txt'
LOCAL_Q = '/tmp/q_batch.txt'

# 风控实测安全线（2026-10-15）：
#   单号详情 ~130 条连发 → 300011 账号异常；~40 条/进程生命周期被杀
# 流控策略：小批次 + 批间长停 + 间隔抖动 + 日封顶
ROUND_CAP = 20          # 每批最多条数（低于 40 杀进程线，留余量）
ROUND_PAUSE = (300, 600)  # 批间停顿秒数（随机）
INTERVAL = (2000, 6000)  # 条间间隔毫秒（随机抖动，拟人）
DAILY_CAP = 60          # 单号单日详情封顶（远低于 130 异常线）


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
    ap.add_argument('--max-rounds', type=int, default=30)
    ap.add_argument('--daily-cap', type=int, default=DAILY_CAP,
                    help='单号单日详情封顶（实测 ~130 触发账号异常）')
    args = ap.parse_args()

    want = [json.loads(l)['note_id'] for l in open(args.list, encoding='utf-8')]
    log(f'目标 {len(want)} 条，日封顶 {args.daily_cap}')

    day_count = 0
    for rd in range(1, args.max_rounds + 1):
        done = captured_ids()
        remain = [i for i in want if i not in done]
        log(f'第 {rd} 轮：已收 {len(done)}/{len(want)}，剩余 {len(remain)}，今日已取 {day_count}')
        if not remain or day_count >= args.daily_cap:
            break
        batch = remain[:ROUND_CAP]
        open(LOCAL_Q, 'w').write('\n'.join(batch))
        adb('push', LOCAL_Q, REMOTE_Q)
        wake_and_launch()
        interval = random.randint(*INTERVAL)
        log(f'本批 {len(batch)} 条，间隔 {interval}ms')
        fire(interval)
        # 等本批跑完或停滞
        est = len(batch) * (interval / 1000 + 0.6)
        t0 = time.time()
        last_n = len(done)
        stall = 0
        while time.time() - t0 < est + 180:
            time.sleep(20)
            n = len(captured_ids())
            if n == last_n:
                stall += 1
                if stall >= 5:   # 100s 无进展 → 进程被杀/账号异常，停
                    log('进度停滞（可能被杀或账号异常），本轮提前结束')
                    break
            else:
                stall = 0
                last_n = n
            if len(captured_ids() & set(batch)) >= len(batch):
                break
        day_count += len(captured_ids() & set(batch))
        if stall >= 5:
            log('异常信号，今天到此为止（避免顶格风控）')
            break
        pause = random.randint(*ROUND_PAUSE)
        log(f'批间停顿 {pause}s')
        time.sleep(pause)

    done = captured_ids() & set(want)
    log(f'完成：{len(done)}/{len(want)}')
    print(json.dumps({'captured': len(done), 'total': len(want)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
