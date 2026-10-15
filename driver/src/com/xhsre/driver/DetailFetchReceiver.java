package com.xhsre.driver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.xingin.notebase.entities.followfeed.BaseNoteFollowFeed;
import com.xingin.notebase.notedetail.service.NoteDetailService;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.reactivex.Observer;

/**
 * 详情批量拉取驱动：收广播 → 读队列文件 → 用 App 自己的 NoteDetailService
 * 逐条发 imagefeed（App 原生签名/会话/线程，与 UI 点开无异）。
 * am broadcast -a com.xhsre.driver.FETCH_DETAILS -p com.xingin.xhsre -f 0x00000020
 *   --es path /sdcard/Android/data/com.xingin.xhsre/files/q.txt [--el interval 1200]
 */
public class DetailFetchReceiver extends BroadcastReceiver {
    public static final String ACTION = "com.xhsre.driver.FETCH_DETAILS";
    private static final String TAG = "XhsDriver";
    private static final AtomicBoolean running = new AtomicBoolean(false);

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!ACTION.equals(intent.getAction())) {
            return;
        }
        String path = intent.getStringExtra("path");
        if (path == null || path.isEmpty()) {
            path = "/sdcard/Android/data/com.xingin.xhsre/files/xhs_detail_queue.txt";
        }
        long interval = intent.getLongExtra("interval", 1200L);
        if (!running.compareAndSet(false, true)) {
            Log.w(TAG, "already running, ignore");
            return;
        }
        final PendingResult pr = goAsync();
        final String fpath = path;
        final long finterval = interval;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    fetchAll(fpath, finterval);
                } catch (Throwable t) {
                    Log.e(TAG, "fetchAll crash", t);
                } finally {
                    running.set(false);
                    pr.finish();
                }
            }
        }, "xhs-driver").start();
    }

    private void fetchAll(String path, long interval) throws Exception {
        List<String> ids = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty()) {
                ids.add(line);
            }
        }
        br.close();
        Log.d(TAG, "queue loaded: " + ids.size() + " notes from " + path);

        NoteDetailService svc = (NoteDetailService) rv9.c.a.b(NoteDetailService.class);
        Log.d(TAG, "service: " + svc);

        int i = 0;
        for (final String nid : ids) {
            i++;
            try {
                // 无 subscribeOn：retrofit rx 适配器在调用线程同步执行 HTTP，
                // 我们在自己的后台线程上，天然串行，节奏由 sleep 控制
                svc.queryNoteDetailFeedData3Up(nid, 1, false, 5, 1,
                        "search", "", "", "", false, "")
                        .subscribe(new Observer<List<BaseNoteFollowFeed>>() {
                            @Override
                            public void onSubscribe(h4d.c d) {
                            }

                            @Override
                            public void onNext(List<BaseNoteFollowFeed> feeds) {
                                Log.d(TAG, "ok " + nid + " " + (feeds == null ? -1 : feeds.size()));
                            }

                            @Override
                            public void onError(Throwable e) {
                                Log.e(TAG, "err " + nid + ": " + e);
                            }

                            @Override
                            public void onComplete() {
                            }
                        });
            } catch (Throwable t) {
                Log.e(TAG, "call fail " + nid, t);
            }
            if (i % 25 == 0) {
                Log.d(TAG, "progress " + i + "/" + ids.size());
            }
            Thread.sleep(interval);
        }
        Log.d(TAG, "DONE " + ids.size());
    }
}
