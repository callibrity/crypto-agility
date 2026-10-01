package com.callibrity.cryptoagility.demos;

import java.math.BigInteger;

/**
 * Pollard's rho: a classical way to find a factor of a number. Its running
 * time grows with the square root of the smallest prime factor, which is why
 * it gets through a 96-bit RSA modulus in a few seconds and is useless against
 * a 3072-bit one.
 */
final class Factoring {

    private static final BigInteger TWO = BigInteger.TWO;
    private static final int BATCH = 256;

    private Factoring() {}

    /** Returns a factor of n other than 1 and n. Only call this with a composite number. */
    static BigInteger findFactor(BigInteger n) {
        if (!n.testBit(0)) {
            return TWO;
        }
        for (long c = 1; ; c++) {
            BigInteger factor = rho(n, BigInteger.valueOf(c));
            if (factor != null) {
                return factor;
            }
        }
    }

    // Walk x one step and y two steps along x -> x*x + c (mod n). When they collide
    // modulo a prime factor p of n, gcd(x - y, n) reveals p. The differences are
    // multiplied together so that the gcd is only taken once per batch.
    private static BigInteger rho(BigInteger n, BigInteger c) {
        BigInteger x = TWO;
        BigInteger y = TWO;
        while (true) {
            BigInteger startX = x;
            BigInteger startY = y;
            BigInteger product = BigInteger.ONE;
            for (int i = 0; i < BATCH; i++) {
                x = step(x, c, n);
                y = step(step(y, c, n), c, n);
                product = product.multiply(x.subtract(y)).mod(n);
            }
            BigInteger g = product.gcd(n);
            if (g.equals(BigInteger.ONE)) {
                continue;
            }
            if (!g.equals(n)) {
                return g;
            }
            // The batch stepped past the factor. Replay it one step at a time.
            x = startX;
            y = startY;
            for (int i = 0; i < BATCH; i++) {
                x = step(x, c, n);
                y = step(step(y, c, n), c, n);
                g = x.subtract(y).gcd(n);
                if (!g.equals(BigInteger.ONE)) {
                    return g.equals(n) ? null : g;      // null: this c failed, try another
                }
            }
            return null;
        }
    }

    private static BigInteger step(BigInteger x, BigInteger c, BigInteger n) {
        return x.multiply(x).add(c).mod(n);
    }
}
