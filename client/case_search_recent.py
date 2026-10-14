#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试用例：搜索关键词，抓最近 N 小时内的帖子详情（不含评论）。

用法：
    python case_search_recent.py --keyword "伦敦 二手" [--hours 24] [--cap 500]
                                 [--sort time_descending] [--target real]

流程：按时间倒序翻搜索页 → 逐条取详情（note/imagefeed）→ 按 note_list[0].time
过滤最近 N 小时 → 整页都超窗即提前停止 → 结果写 JSONL（剥离 comment_list）。
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xhs_api import XhsClient, HOST, log  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def search_page(client, keyword, page, sort, search_id, session_id, page_size=20):
    """完整参数集（对齐 rc0.h 构建器），缺参会 500 NPE。
    search_id/session_id 必须一次搜索会话固定——每页换新会被服务端当成
    全新搜索，导致翻页结果大量重复。"""
    params = {
        'keyword': keyword, 'filters': '', 'sort': sort,
        'page': page, 'page_size': page_size, 'source': 'explore',
        'search_id': search_id, 'session_id': session_id,
        'api_extra': '', 'page_pos': 0, 'ext_params': '', 'pin_note_id': '',
        'allow_rewrite': 1, 'geo': '', 'loaded_ad': '',
        'query_extra_info': '', 'rec_extra_params': '', 'scene': 'search',
        'is_optimize': 0, 'location_permission': 0, 'device_level': 2,
        'refresh_type': 1, 'exp_infos': '', 'feed_oaid': '',
        'known_signal': '', 'ai_mode': 0, 'search_tab': 'notes',
    }
    url = f'{HOST}/api/sns/v10/search/notes?' + urllib.parse.urlencode(params)
    r = client._send_via_device('GET', url)
    j = json.loads(r.text or '{}')
    return j, client.parse_search_items(j)


def fetch_detail(client, note_id, xsec_token, retries=2):
    for attempt in range(retries + 1):
        try:
            r = client.get_note(note_id, xsec_token)
            j = json.loads(r.text or '{}')
            if j.get('success'):
                return j
            log(f'详情 {note_id} 返回 code={j.get("code")} msg={j.get("msg")}')
            return j
        except Exception as e:
            log(f'详情 {note_id} 异常（{type(e).__name__}: {str(e)[:60]}）'
                + (f'，{3}s 后重试' if attempt < retries else '，放弃'))
            if attempt < retries:
                time.sleep(3)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keyword', default='伦敦 二手')
    ap.add_argument('--hours', type=float, default=24)
    ap.add_argument('--cap', type=int, default=500)
    ap.add_argument('--sort', default='time_descending')
    ap.add_argument('--target', default=os.environ.get('XHS_TARGET', 'real'))
    ap.add_argument('--out', default='')
    ap.add_argument('--page-size', type=int, default=20)
    ap.add_argument('--detail-sleep', type=float, default=0.4)
    args = ap.parse_args()

    cutoff = time.time() - args.hours * 3600
    if not args.out:
        ts = time.strftime('%Y%m%d_%H%M%S')
        safe = args.keyword.replace(' ', '_')
        args.out = os.path.join(HERE, 'out', f'search_{safe}_{ts}.jsonl')
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    client = XhsClient(spawn=False, target=args.target, ready_timeout=90)
    log(f'关键词="{args.keyword}" 窗口={args.hours}h 封顶={args.cap} 输出={args.out}')

    kept = 0
    seen = set()
    page = 1
    empty_pages = 0
    dup_pages = 0
    max_pages = 100          # 硬上限，防翻页死循环
    search_id = uuid.uuid4().hex
    session_id = uuid.uuid4().hex
    with open(args.out, 'w', encoding='utf-8') as fout:
        while kept < args.cap:
            try:
                j, items = search_page(client, args.keyword, page, args.sort,
                                       search_id, session_id, args.page_size)
            except Exception as e:
                log(f'第 {page} 页搜索失败（{type(e).__name__}: {str(e)[:60]}），'
                    '10s 后重试一次')
                time.sleep(10)
                j, items = search_page(client, args.keyword, page, args.sort,
                                       search_id, session_id, args.page_size)
            fresh = [it for it in items if it.get('note_id')]
            log(f'第 {page} 页：{len(fresh)} 条有效（共 {len(items)} 条）')
            if not fresh:
                empty_pages += 1
                if empty_pages >= 2:
                    log('连续两页空，到底了')
                    break
                page += 1
                time.sleep(1)
                continue
            empty_pages = 0

            page_kept = 0
            page_old = 0
            page_new = 0
            for it in fresh:
                nid = it['note_id']
                if nid in seen:
                    continue
                seen.add(nid)
                page_new += 1
                dj = fetch_detail(client, nid, it.get('xsec_token', ''))
                time.sleep(args.detail_sleep)
                if not dj:
                    continue
                data = dj.get('data') or []
                if not isinstance(data, list) or not data:
                    continue
                entry = data[0]
                notes = entry.get('note_list') or []
                if not notes:
                    continue
                note = notes[0]
                ntime = note.get('time') or 0
                if ntime < cutoff:
                    page_old += 1
                    continue
                entry = dict(entry)
                entry.pop('comment_list', None)   # 不要评论，其他全留
                rec = {
                    'note_id': nid,
                    'xsec_token': it.get('xsec_token', ''),
                    'time': ntime,
                    'time_iso': time.strftime('%Y-%m-%dT%H:%M:%S',
                                              time.localtime(ntime)),
                    'detail': entry,
                }
                fout.write(json.dumps(rec, ensure_ascii=False) + '\n')
                fout.flush()
                kept += 1
                page_kept += 1
                log(f'  [{kept}] {rec["time_iso"]} {str(note.get("title"))[:40]}')
                if kept >= args.cap:
                    break
            log(f'第 {page} 页：新 {page_new} 条，入 {page_kept} 条，超窗 {page_old} 条')
            # 时间倒序下整页都超窗 = 后面更老，收工
            if page_kept == 0 and page_old > 0:
                log('整页超窗，停止翻页')
                break
            # 整页都是已见过的重复 = 分页耗尽，收工
            if page_new == 0:
                dup_pages += 1
                if dup_pages >= 3:
                    log('连续 3 页纯重复，分页耗尽，停止')
                    break
            else:
                dup_pages = 0
            page += 1
            if page > max_pages:
                log(f'到达页数硬上限 {max_pages}，停止')
                break
            time.sleep(0.8)

    log(f'完成：共抓 {kept} 条 → {args.out}')


if __name__ == '__main__':
    main()
