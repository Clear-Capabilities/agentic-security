public class Work {
    static int stretch(byte[] seed, int cost) {
        long iterations;
        if (cost < 4 || cost > 31)
            throw new IllegalArgumentException("cost");
        iterations = 1L << cost;
        int acc = 0;
        for (long r = 0; r < iterations; r++) acc += seed[(int) (r % seed.length)];
        return acc;
    }

    public static void checkSpan(byte[] buf, int off, int len) {
        if (off < 0 || len < 0 || off > buf.length - len) {
            throw new ArrayIndexOutOfBoundsException(off);
        }
    }
}
