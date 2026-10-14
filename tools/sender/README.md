# xhs-sender：设备侧发送守护进程

脱离 xhs App 进程的 HTTP 发送器。`app_process` 托管，HttpsURLConnection 直连，
无看门狗、无自杀。与 App 内 rawfetch 同通道可信度（A/B 实验见 docs 第九节）。

## 编译（需要 JDK + Android SDK build-tools）

```bash
javac -source 8 -target 8 -cp $SDK/platforms/android-36/android.jar Sender.java
mkdir -p classes && mv *.class classes/
(cd classes && d8 --release --min-api 24 --output .. *.class)   # 产物 classes.dex
```

## 部署与运行

```bash
adb -s <serial> push classes.dex /data/local/tmp/sender.dex
adb -s <serial> shell "CLASSPATH=/data/local/tmp/sender.dex setsid app_process / Sender 27046 \
  > /data/local/tmp/sender.log 2>&1 < /dev/null &"
```

客户端（`client/xhs_api.py` 的 `DaemonSender`）会自动 forward + 拉起，直接用：

```bash
XHS_VIA=daemon python xhs_api.py --target real search "关键词"
```

## 协议

TCP 127.0.0.1:27046，JSON 行：
请求 `{"id":1,"method":"GET","url":"...","headers":[["k","v"]],"bodyB64":"..."}`
响应 `{"id":1,"code":200,"headers":[["k","v"]],"body":"..."}` 或 `{"fetchError":"..."}`
