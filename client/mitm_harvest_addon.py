"""mitmproxy 收割插件：把目标接口的响应体落盘 JSONL。

用法：mitmdump --listen-port 8082 -s mitm_harvest_addon.py -q
输出：/tmp/xhs_harvest.jsonl，每行 {ts,url,code,body}
"""
import json
import time

from mitmproxy import http

TARGETS = (
    '/api/sns/v10/search/notes',
    '/api/sns/v3/search/notes',
    '/api/sns/v6/homefeed',
    '/api/sns/v1/note/',        # imagefeed 等笔记详情族
    '/api/sns/v2/note/',        # 视频笔记详情
    '/api/sns/v3/note/',
)
OUT = '/tmp/xhs_harvest.jsonl'


def response(flow: http.HTTPFlow):
    if flow.response is None:
        return
    if not any(t in flow.request.path for t in TARGETS):
        return
    try:
        body = flow.response.get_text(strict=False) or ''
    except Exception:
        body = ''
    rec = {
        'ts': time.time(),
        'url': flow.request.pretty_url,
        'code': flow.response.status_code,
        'body': body,
    }
    with open(OUT, 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')
