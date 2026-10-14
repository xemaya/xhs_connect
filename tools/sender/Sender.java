import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;

/**
 * 设备侧发送守护进程：app_process 托管，与 xhs App 进程完全无关。
 * TCP 监听 127.0.0.1:27046（Mac 经 adb forward 连入），JSON 行协议：
 *   请求: {"id":1,"method":"GET","url":"...","headers":[["k","v"]],"bodyB64":"..."}
 *   响应: {"id":1,"code":200,"headers":[["k","v"]],"body":"..."}
 */
public class Sender {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 27046;
        ServerSocket srv = new ServerSocket(port, 8,
                InetAddress.getByName("127.0.0.1"));
        log("sender listening on 127.0.0.1:" + port);
        while (true) {
            Socket s;
            try {
                s = srv.accept();
            } catch (IOException e) {
                continue;
            }
            final Socket sock = s;
            new Thread(new Runnable() {
                public void run() {
                    try {
                        handle(sock);
                    } catch (Throwable t) {
                        log("conn error: " + t);
                    }
                }
            }).start();
        }
    }

    static void handle(Socket sock) throws IOException {
        sock.setSoTimeout(60000);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(sock.getInputStream(), "UTF-8"));
        OutputStream out = sock.getOutputStream();
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            Map<String, Object> req;
            try {
                req = (Map<String, Object>) new Json(line).parse();
            } catch (Throwable t) {
                writeJson(out, "{\"error\":\"bad json\"}");
                continue;
            }
            Object id = req.get("id");
            Map<String, Object> resp = new LinkedHashMap<String, Object>();
            resp.put("id", id);
            try {
                String method = str(req.get("method"), "GET");
                String url = str(req.get("url"), "");
                List<List<String>> headers =
                        (List<List<String>>) req.get("headers");
                byte[] body = null;
                Object b64 = req.get("bodyB64");
                if (b64 != null && !((String) b64).isEmpty()) {
                    body = Base64.getDecoder().decode((String) b64);
                }
                Map<String, Object> r = doFetch(method, url, headers, body);
                resp.putAll(r);
            } catch (Throwable t) {
                resp.put("fetchError", String.valueOf(t));
            }
            writeJson(out, Json.write(resp));
        }
    }

    static Map<String, Object> doFetch(String method, String urlStr,
                                       List<List<String>> headers,
                                       byte[] body) throws IOException {
        HttpURLConnection conn =
                (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        conn.setInstanceFollowRedirects(false);
        if (headers != null) {
            for (List<String> kv : headers) {
                if (kv.size() == 2) conn.setRequestProperty(kv.get(0), kv.get(1));
            }
        }
        if (body != null && body.length > 0) {
            conn.setRequestMethod(method);
            conn.setDoOutput(true);
            OutputStream os = conn.getOutputStream();
            os.write(body);
            os.flush();
            os.close();
        } else {
            conn.setRequestMethod(method);
        }
        int code = conn.getResponseCode();
        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        if (is != null) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            is.close();
        }
        List<List<String>> hs = new ArrayList<List<String>>();
        for (int i = 1; ; i++) {
            String k = conn.getHeaderFieldKey(i);
            if (k == null) break;
            hs.add(Arrays.asList(k, conn.getHeaderField(i)));
            if (i > 64) break;
        }
        conn.disconnect();
        Map<String, Object> r = new LinkedHashMap<String, Object>();
        r.put("code", code);
        r.put("headers", hs);
        r.put("body", bos.toString("UTF-8"));
        return r;
    }

    static void writeJson(OutputStream out, String s) throws IOException {
        out.write(s.getBytes("UTF-8"));
        out.write('\n');
        out.flush();
    }

    static String str(Object o, String dft) {
        return o == null ? dft : String.valueOf(o);
    }

    static void log(String m) {
        System.err.println("[sender] " + m);
    }

    /* ---------- 极简 JSON（免依赖） ---------- */
    static class Json {
        private final String s;
        private int p;

        Json(String s) { this.s = s; }

        Object parse() { skipWs(); return value(); }

        private void skipWs() {
            while (p < s.length() && Character.isWhitespace(s.charAt(p))) p++;
        }

        private Object value() {
            skipWs();
            char c = s.charAt(p);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't') { p += 4; return Boolean.TRUE; }
            if (c == 'f') { p += 5; return Boolean.FALSE; }
            if (c == 'n') { p += 4; return null; }
            return number();
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            p++;
            skipWs();
            if (s.charAt(p) == '}') { p++; return m; }
            while (true) {
                skipWs();
                String k = string();
                skipWs();
                p++; // ':'
                m.put(k, value());
                skipWs();
                char c = s.charAt(p++);
                if (c == '}') break;
            }
            return m;
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<Object>();
            p++;
            skipWs();
            if (s.charAt(p) == ']') { p++; return l; }
            while (true) {
                l.add(value());
                skipWs();
                char c = s.charAt(p++);
                if (c == ']') break;
            }
            return l;
        }

        private String string() {
            StringBuilder sb = new StringBuilder();
            p++; // '"'
            while (true) {
                char c = s.charAt(p++);
                if (c == '"') break;
                if (c == '\\') {
                    char e = s.charAt(p++);
                    switch (e) {
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        case 'r': sb.append('\r'); break;
                        case 'u':
                            sb.append((char) Integer.parseInt(
                                    s.substring(p, p + 4), 16));
                            p += 4;
                            break;
                        default: sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Object number() {
            int st = p;
            while (p < s.length() && "-+0123456789.eE".indexOf(s.charAt(p)) >= 0) p++;
            String t = s.substring(st, p);
            if (t.contains(".") || t.contains("e") || t.contains("E")) {
                return Double.parseDouble(t);
            }
            try {
                return Integer.parseInt(t);
            } catch (NumberFormatException e) {
                return Long.parseLong(t);
            }
        }

        static String write(Object o) {
            StringBuilder sb = new StringBuilder();
            writeTo(sb, o);
            return sb.toString();
        }

        static void writeTo(StringBuilder sb, Object o) {
            if (o == null) { sb.append("null"); return; }
            if (o instanceof String) { quote(sb, (String) o); return; }
            if (o instanceof Number || o instanceof Boolean) {
                sb.append(o.toString());
                return;
            }
            if (o instanceof Map) {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    quote(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    writeTo(sb, e.getValue());
                }
                sb.append('}');
                return;
            }
            if (o instanceof List) {
                sb.append('[');
                boolean first = true;
                for (Object it : (List<?>) o) {
                    if (!first) sb.append(',');
                    first = false;
                    writeTo(sb, it);
                }
                sb.append(']');
                return;
            }
            quote(sb, String.valueOf(o));
        }

        static void quote(StringBuilder sb, String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
        }
    }
}
