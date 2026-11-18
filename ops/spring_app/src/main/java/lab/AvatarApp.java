package lab;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** Avatar service — decode(java.util.Base64) → cache → GET returns cached bytes.
 *  Real Spring Boot / Tomcat, default config, ordinary-user post-auth (X-User header). */
@SpringBootApplication
@RestController
public class AvatarApp {
    static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();
    static final int MAX = 200;

    public static void main(String[] args) {
        System.err.println("[app] starting, java=" + System.getProperty("java.version"));
        SpringApplication.run(AvatarApp.class, args);
    }

    static String user(String h) {
        if (h == null || h.isEmpty()) throw new RuntimeException("no user");
        return h;
    }

    @PostMapping("/api/avatar")
    public ResponseEntity<String> put(@RequestHeader(value = "X-User", required = false) String user,
                                      @RequestParam String id,
                                      @RequestBody byte[] body) throws Exception {
        user(user);
        String b64 = new String(body, java.nio.charset.StandardCharsets.ISO_8859_1).trim();
        byte[] out = Base64.getDecoder().decode(b64);   // ← CVE-2026-114938 intrinsic path
        if (CACHE.size() >= MAX) CACHE.clear();
        CACHE.put(id, out);
        return ResponseEntity.ok("{\"id\":\"" + id + "\",\"len\":" + out.length + ",\"cached\":" + CACHE.size() + "}\n");
    }

    @GetMapping("/api/avatar")
    public ResponseEntity<byte[]> get(@RequestHeader(value = "X-User", required = false) String user,
                                      @RequestParam String id) {
        user(user);
        byte[] v = CACHE.get(id);
        if (v == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok().header("X-Cached-Len", String.valueOf(v.length)).body(v);
    }

    @DeleteMapping("/api/avatar")
    public ResponseEntity<String> del(@RequestHeader(value = "X-User", required = false) String user,
                                      @RequestParam String id) {
        user(user);
        byte[] gone = CACHE.remove(id);
        return ResponseEntity.ok("{\"dropped\":\"" + id + "\",\"was\":" + (gone == null ? -1 : gone.length) + "}\n");
    }

    /** GC pump — young garbage to drive concurrent cycles (no humongous) */
    @PostMapping("/api/pump")
    public ResponseEntity<String> pump(@RequestParam int mb) {
        for (int i = 0; i < mb * 4; i++) { byte[] t = new byte[256 * 1024]; t[0] = 1; }
        return ResponseEntity.ok("{\"pumpedMB\":" + mb + "}\n");
    }

    static final Base64.Decoder DEC = Base64.getDecoder();
    /** Thread-local reused decode buffer — real Basic-auth apps precompute/reuse.
     *  decode(src, dst) two-arg form: CVE-2026-114938 underflow writes 64B at dst+48,
     *  overflowing this 64B buffer by 48B into the NEXT TLAB allocation (username bytes). */
    static final ThreadLocal<byte[]> SCRATCH = ThreadLocal.withInitial(() -> new byte[64]);

    /** Basic-auth login — decodes attacker-controlled b64 PRE-AUTH (like every Java app). */
    @GetMapping("/api/login")
    public ResponseEntity<String> login(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        if (auth == null || !auth.startsWith("Basic ")) {
            return ResponseEntity.status(401)
                .header("WWW-Authenticate", "Basic realm=\"lab\"").body("401 auth required\n");
        }
        byte[] src = auth.substring(6).trim().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] dst = SCRATCH.get();
        int dp;
        try {
            dp = DEC.decode(src, dst);   // ← CVE-2026-114938 intrinsic underflow (65B b64 text)
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(401).body("401 bad base64\n");
        }
        String credStr = new String(dst, 0, dp, java.nio.charset.StandardCharsets.ISO_8859_1);
        int colon = credStr.indexOf(':');
        String username = colon >= 0 ? credStr.substring(0, colon) : credStr;
        if ("admin".equals(username) && colon >= 0
                && "admin".equals(credStr.substring(colon + 1))) {
            return ResponseEntity.ok("{\"login\":\"ok\"}\n");
        }
        // echo username in the failure — JavaBleed channel
        return ResponseEntity.status(401)
            .body("401 login failed for user: " + username + "\n");
    }

    /** Diagnostic — read each cached array's length DIRECTLY from the header
     *  (catches OOB-smashed lengths instantly; corrupt sign/rotation observable) */
    @GetMapping("/api/diag")
    public ResponseEntity<String> diag() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, byte[]> e : CACHE.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue().length);
        }
        sb.append('}');
        return ResponseEntity.ok(sb.toString());
    }

    @GetMapping("/api/status")
    public ResponseEntity<String> status() {
        long bytes = 0;
        for (byte[] b : CACHE.values()) bytes += b.length;
        return ResponseEntity.ok("{\"cached\":" + CACHE.size() + ",\"bytes\":" + bytes + "}\n");
    }
}
