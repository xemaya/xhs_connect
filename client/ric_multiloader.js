var hooked = 0, already = 0, failed = 0;
S.ricHooked = S.ricHooked || {};
Java.enumerateClassLoaders({
  onMatch: function (loader) {
    var key = '' + loader;
    if (S.ricHooked[key]) { already++; return; }
    try {
      var factory = Java.ClassFactory.get(loader);
      var RIC = factory.use('okhttp3.internal.http.RealInterceptorChain');
      S.ricHooked[key] = 1;
      var impl = function (req) {
        var isEdith = false;
        var u = '';
        try {
          u = req.url().toString();
          isEdith = u.indexOf('edith.xiaohongshu.com') >= 0;
          if (isEdith && S.recentUrls.indexOf(u) < 0) {
            S.recentUrls.push(u);
            if (S.recentUrls.length > 20) S.recentUrls.shift();
          }
        } catch (e) {}
        var resp = this.proceed(req);
        if (isEdith) {
          try {
            var last = S.recentResp[S.recentResp.length - 1];
            if (!last || last[0] !== u) {
              S.recentResp.push([u.split('?')[0], resp.code()]);
              if (S.recentResp.length > 30) S.recentResp.shift();
            }
          } catch (e) {}
          try {
            if (u.indexOf('/api/sns/v10/search/notes') >= 0
                || u.indexOf('/api/sns/v1/note/imagefeed') >= 0
                || u.indexOf('/api/sns/v6/homefeed') >= 0) {
              var b = resp.peekBody(4 * 1024 * 1024).string();
              S.harvest.push({ url: u, code: resp.code(), body: b });
              if (S.harvest.length > 80) S.harvest.shift();
              log('收割(插件loader) ' + resp.code() + ' ' + u.split('?')[0] + ' (' + b.length + 'B)');
            }
          } catch (e2) {}
        }
        return resp;
      };
      var m = RIC.proceed;
      try { m.overload('okhttp3.Request').implementation = impl; }
      catch (e) { m.implementation = impl; }
      hooked++;
    } catch (e) { failed++; }
  },
  onComplete: function () {}
});
return { hooked: hooked, already: already, failed: failed };
