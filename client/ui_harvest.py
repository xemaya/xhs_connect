#!/usr/bin/env python3
"""UI 驱动收割：同一 RPC 会话内驱动 xhsre 搜索页滚动，收割 App 自己发的响应。

用法：
  python ui_harvest.py --keyword '伦敦 二手' --cap 500 --scrolls 60

流程：
  1. 连入 gadget（复用在线通道，不重载脚本）
  2. evaljs 强制补装 RealInterceptorChain hook（连接时 tiny 未就绪会漏装）
  3. adb 点开搜索页 → ADBKeyBoard 输入关键词 → 点搜索
  4. 循环：滚动一屏 → 等加载 → harvest(0) 快照累积新 items
  5. 落盘 JSONL（note_id/xsec_token/title/... 复用 parse_search_items）

安全：每步操作前校验 mCurrentFocus 仍是 com.xingin.xhsre，否则中止。
"""
import argparse
import base64
import json
import subprocess
import sys
import time

from xhs_api import XhsClient, ADB, TARGETS, log

SERIAL = TARGETS['real']['serial']
PKG = TARGETS['real']['pkg']


def adb(*args, timeout=30):
    return subprocess.run([ADB, '-s', SERIAL] + list(args),
                          capture_output=True, text=True, timeout=timeout).stdout.strip()


def focus():
    out = adb('shell', 'dumpsys', 'window')
    for line in out.splitlines():
        if 'mCurrentFocus' in line:
            return line.strip()
    return ''


def focus_ok():
    return PKG in focus()


def ensure_focus_or_die():
    if focus_ok():
        return
    # 熄屏/launcher：尝试亮屏解锁拉起一次
    adb('shell', 'input', 'keyevent', '224')
    time.sleep(1)
    adb('shell', 'input', 'swipe', '500', '1800', '500', '600')
    time.sleep(1)
    adb('shell', 'am', 'start', '-n', f'{PKG}/com.xingin.xhs.index.v2.IndexActivityV2')
    time.sleep(4)
    if not focus_ok():
        raise RuntimeError('焦点不在 xhsre，中止（当前: ' + focus() + '）')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keyword', required=True)
    ap.add_argument('--cap', type=int, default=500)
    ap.add_argument('--scrolls', type=int, default=60)
    ap.add_argument('--scroll-sleep', type=float, default=3.0)
    ap.add_argument('--out', default=None)
    ap.add_argument('--target', default='real')
    args = ap.parse_args()

    out_path = args.out or f"out/ui_harvest_{args.keyword.replace(' ', '_')}_{int(time.time())}.jsonl"

    log('连接签名通道（复用在线脚本实例）...')
    c = XhsClient(spawn=False, target=args.target)

    # 关键：补装样本/收割 hook（脚本载入时 tiny 未就绪会跳过，且不重试）
    r = c._rpc('evaljs', 'ensureHooks(true); return {sample: S.sampleHookOk, err: S.lastErr};')
    log('hook 状态: ' + r)
    if not json.loads(r).get('sample'):
        raise RuntimeError('收割 hook 安装失败')

    seen_resp = set()   # 已见过的响应 url（去重，快照非 drain）
    items = {}          # note_id -> item

    # 清掉滚动前已有的旧收割（例如首页 feed），只留搜索响应也行，直接全清
    c._rpc('harvest', 1)

    # ---- 拉起搜索页 ----
    ensure_focus_or_die()
    adb('shell', 'input', 'tap', '1000', '190')   # 首页右上角放大镜
    time.sleep(3)
    if 'GlobalSearch' not in focus():
        raise RuntimeError('未进入搜索页：' + focus())

    b64 = base64.b64encode(args.keyword.encode()).decode()
    adb('shell', 'am', 'broadcast', '-a', 'ADB_INPUT_B64', '--es', 'msg', b64)
    time.sleep(1.5)
    ensure_focus_or_die()
    adb('shell', 'input', 'tap', '988', '186')    # 搜索按钮
    log(f'已触发搜索：{args.keyword}')
    time.sleep(5)

    def drain_search_responses():
        """读快照（不 drain），把搜索响应里的新 items 并入 items。"""
        snap = c._rpc('harvest', 0) or []
        new_items = 0
        for it in snap:
            key = (it.get('url') or '') + '|' + str(it.get('code'))
            if key in seen_resp:
                continue
            seen_resp.add(key)
            url = it.get('url') or ''
            body = it.get('body') or ''
            if '/api/sns/v10/search/notes' not in url:
                log(f"收割到非搜索响应 {it.get('code')} {url.split('?')[0]} ({len(body)}B)")
                continue
            log(f"搜索响应 {it.get('code')} ({len(body)}B)")
            try:
                j = json.loads(body)
            except Exception:
                log('  body 非 JSON，跳过')
                continue
            if not j.get('success'):
                log(f"  success=false: {json.dumps(j, ensure_ascii=False)[:200]}")
                continue
            for it2 in XhsClient.parse_search_items(j):
                if it2['note_id'] not in items:
                    items[it2['note_id']] = it2
                    new_items += 1
        return new_items

    # ---- 滚动收割 ----
    stall = 0
    for i in range(args.scrolls):
        if not focus_ok():
            log('焦点丢失，尝试恢复')
            ensure_focus_or_die()
            # 恢复后可能回到首页，中止更安全
            if 'GlobalSearch' not in focus():
                log('恢复后不在搜索页，中止滚动（已收 %d 条）' % len(items))
                break
        drain_search_responses()
        n0 = len(items)
        adb('shell', 'input', 'swipe', '540', '1800', '540', '600', '800')
        time.sleep(args.scroll_sleep)
        drain_search_responses()
        log(f'滚动 {i + 1}/{args.scrolls}：累计 {len(items)} 条')
        if len(items) >= args.cap:
            log('达到封顶')
            break
        if len(items) == n0:
            stall += 1
            if stall >= 8:
                log('连续 8 屏无新内容，到底了')
                break
        else:
            stall = 0

    # ---- 落盘 ----
    with open(out_path, 'w', encoding='utf-8') as f:
        for it in items.values():
            f.write(json.dumps(it, ensure_ascii=False) + '\n')
    log(f'完成：{len(items)} 条 → {out_path}')
    print(json.dumps({'count': len(items), 'out': out_path}, ensure_ascii=False))


if __name__ == '__main__':
    main()
