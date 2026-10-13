# xhs_connect

小红书 App（com.xingin.xhs）逆向与协议直连项目：借助设备上运行的 App 自身的 native 签名能力（frida RPC），从宿主机 Python 直接调用搜索 / 首页 / 帖子详情等接口。

## 架构

```
Python (xhs_api.py)
   │  ① 拼 URL/参数
   ▼
frida RPC ──► 设备上的小红书进程
   │            ├─ idb.f.h()            → x-mini-mua / x-mini-s1 / x-mini-sig（libtiny）
   │            ├─ XhsHttpInterceptor    → shield / xy-platform-info（libxyass，假 OkHttp Chain 喂入）
   │            └─ mhb.r / hjc.n1 / n2c.b → x-legacy-did / fid / sid
   │  ② 返回完整签名头
   ▼
requests ──► edith.xiaohongshu.com
```

签名永远与线上版本同步，无需离线复算 native 算法。

## 目录

- `client/` — 可运行的客户端（sign.js = frida 脚本，xhs_api.py = Python 客户端，用法见 `client/README.md`）
- `docs/小红书-链路逆向分析.md` — 搜索/推荐/详情接口 URL、参数、xsec_token 来源
- `docs/小红书-shield签名算法.md` — libxyass shield 头算法完全还原（RC4+HMAC-MD5，Unicorn 验证）
- `docs/小红书-tiny签名算法.md` — libtiny x-mini-sig 算法还原（SHA256 preimage 已验证）
- `docs/小红书-登录链路逆向分析.md` — 短信/密码登录协议、secure 参数 AES 还原、登录态携带方式
- `docs/真机迁移与现场情况.md` — **当前现场状态、反调试对抗经验、已知问题（必读）**

## 当前状态速览（2026-10-13）

| 能力 | 状态 |
|---|---|
| GET 签名 + 首页 homefeed | ✅ 模拟器/真机均 200 出数据 |
| POST 签名 | ✅ 已实现（form body 参与 tiny/shield 摘要） |
| 密码/短信登录协议 | ⚠️ 协议全通；模拟器被风控挡（300012 IP 风险），真机待验证 |
| 搜索 / 详情 | ⚠️ 需正式登录态（游客态返回 -100/406），等登录闭环 |

## 红线

- 真机上官方包 `com.xingin.xhs` 与重打包副本 `com.xingin.xhsre` **共存**，任何操作不得触碰官方包及其数据
- 仓库不提交：APK 文件、签名密钥、真实账号凭据、session.json
