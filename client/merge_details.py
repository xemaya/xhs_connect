#!/usr/bin/env python3
"""把 /tmp/xhs_harvest.jsonl 里的 imagefeed 响应解析成干净详情 JSONL。

用法：python merge_details.py [--out out/伦敦二手_详情合并.jsonl]
"""
import argparse
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HARVEST_JSONL = '/tmp/xhs_harvest.jsonl'


def parse_detail(j):
    """imagefeed 响应：data[0].note_list[0] 本体，user/comment_list 同级。"""
    data = j.get('data') or []
    if not isinstance(data, list) or not data:
        return None
    entry = data[0]
    notes = entry.get('note_list') or []
    if not notes:
        return None
    n = notes[0]
    user = entry.get('user') or n.get('user') or {}
    images = []
    for im in n.get('images_list') or []:
        u = im.get('url_size_large') or im.get('url') or ''
        if u:
            images.append(u)
    video = ''
    v = (n.get('video') or {})
    try:
        stream = v['media']['stream']
        for fmt in ('h264', 'h265', 'av1'):
            arr = stream.get(fmt) or []
            if arr and arr[0].get('master_url'):
                video = arr[0]['master_url']
                break
    except Exception:
        pass
    inter = n.get('interact_info') or {}
    ts = n.get('time') or n.get('last_update_time') or 0
    if ts and ts < 10 ** 11:
        ts *= 1000
    return {
        'note_id': n.get('note_id') or n.get('id') or '',
        'title': n.get('title') or '',
        'desc': n.get('desc') or '',
        'type': n.get('type') or '',
        'time': ts,
        'time_iso': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts / 1000)) if ts else '',
        'ip_location': n.get('ip_location') or '',
        'liked_count': inter.get('liked_count') or inter.get('likedCount'),
        'collected_count': inter.get('collected_count') or inter.get('collectedCount'),
        'comments_count': inter.get('comment_count') or inter.get('commentCount'),
        'shared_count': inter.get('shared_count') or inter.get('sharedCount'),
        'user': user.get('nickname') or user.get('name') or '',
        'user_id': user.get('user_id') or user.get('userid') or '',
        'red_id': user.get('red_id') or '',
        'images': images,
        'video_url': video,
        'tag_list': [t.get('name') for t in (n.get('tag_list') or []) if t.get('name')],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(HERE, 'out', '伦敦二手_详情合并.jsonl'))
    ap.add_argument('--harvest', default=HARVEST_JSONL)
    args = ap.parse_args()

    details = {}
    for line in open(args.harvest, encoding='utf-8'):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if '/api/sns/v1/note/imagefeed' not in rec.get('url', ''):
            continue
        try:
            j = json.loads(rec.get('body') or '')
        except Exception:
            continue
        d = parse_detail(j)
        if d and d['note_id']:
            details[d['note_id']] = d

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        for d in details.values():
            f.write(json.dumps(d, ensure_ascii=False) + '\n')
    print(json.dumps({'details': len(details), 'out': args.out}, ensure_ascii=False))


if __name__ == '__main__':
    main()
