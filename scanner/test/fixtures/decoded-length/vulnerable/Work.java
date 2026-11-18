public class Work {
    static int stretch(byte[] seed, int cost) {
        int iterations, i;
        if (cost < 4 || cost > 31)
            throw new IllegalArgumentException("cost");
        iterations = 1 << cost;
        int acc = 0;
        for (i = 0; i < iterations; i++) acc += seed[i % seed.length];
        return acc;
    }

    public static void checkSpan(byte[] buf, int off, int len) {
        if (off < 0 || len < 0 || off + len > buf.length) {
            throw new ArrayIndexOutOfBoundsException(off);
        }
    }
}
