package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DELIBERATELY BROKEN. RSA with a key so short that a laptop can factor it in
 * a few seconds, so that ./demo crack has something it can actually break.
 *
 * Real RSA is not broken this way today: RsaWrapper uses a 3072-bit key, far
 * out of reach of any classical computer. This class shrinks the key so you can
 * watch what happens to an envelope once its wrapping algorithm falls, which
 * is what Shor's algorithm on a large quantum computer would do to real RSA.
 *
 * It is also textbook RSA with no padding, done by hand with BigInteger,
 * because the JDK rightly refuses to make RSA keys this small. Never use any of
 * this for real data.
 */
public final class ToyRsaWrapper implements KeyWrapper, Inventoried {

    /** Sets how long the crack takes: about 0.2 s at 80 bits, a few seconds at 96, around 15 s at 104. */
    public static final int MODULUS_BITS = 96;
    public static final String ALG_ID = "RSA-TOY-" + MODULUS_BITS;

    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final int DEK_BYTES = 32;
    private static final String WRAPPED_KEY = "wrappedKey";

    /** The half anyone may see. Knowing the factors of the modulus is as good as knowing the private key. */
    public record PublicKey(BigInteger modulus, BigInteger exponent) {

        public Map<String, String> toFields() {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("modulus", modulus.toString());
            fields.put("exponent", exponent.toString());
            return fields;
        }

        public static PublicKey fromFields(Map<String, String> fields) {
            return new PublicKey(new BigInteger(fields.get("modulus")), new BigInteger(fields.get("exponent")));
        }
    }

    /** The public key together with the private exponent that undoes it. */
    public record Keys(PublicKey publicKey, BigInteger privateExponent) {

        /** Rebuilds the private exponent from one prime factor of the modulus. This is the whole attack. */
        public static Keys fromFactor(PublicKey publicKey, BigInteger p) {
            BigInteger q = publicKey.modulus().divide(p);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            return new Keys(publicKey, publicKey.exponent().modInverse(phi));
        }

        public Map<String, String> toFields() {
            Map<String, String> fields = publicKey.toFields();
            fields.put("privateExponent", privateExponent.toString());
            return fields;
        }

        public static Keys fromFields(Map<String, String> fields) {
            return new Keys(PublicKey.fromFields(fields), new BigInteger(fields.get("privateExponent")));
        }
    }

    private final Keys keys;

    public ToyRsaWrapper() {
        this(newKeys());
    }

    public ToyRsaWrapper(Keys keys) {
        this.keys = keys;
    }

    public static Keys newKeys() {
        var rng = new SecureRandom();
        while (true) {
            BigInteger p = BigInteger.probablePrime(MODULUS_BITS / 2, rng);
            BigInteger q = BigInteger.probablePrime(MODULUS_BITS / 2, rng);
            BigInteger n = p.multiply(q);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            if (!p.equals(q) && n.bitLength() == MODULUS_BITS && phi.gcd(PUBLIC_EXPONENT).equals(BigInteger.ONE)) {
                return Keys.fromFactor(new PublicKey(n, PUBLIC_EXPONENT), p);
            }
        }
    }

    @Override
    public String algId() { return ALG_ID; }

    // The modulus is smaller than the data key, so the key is cut into chunks and each is encrypted on its own.
    @Override
    public WrappedDek wrap(SecretKey dek) {
        BigInteger n = keys.publicKey().modulus();
        byte[] plain = dek.getEncoded();
        var out = new ByteArrayOutputStream();
        for (int from = 0; from < plain.length; from += chunkBytes(n)) {
            int to = Math.min(from + chunkBytes(n), plain.length);
            BigInteger m = new BigInteger(1, Arrays.copyOfRange(plain, from, to));
            out.writeBytes(fixedWidth(m.modPow(keys.publicKey().exponent(), n), blockBytes(n)));
        }
        return WrappedDek.of(WRAPPED_KEY, out.toByteArray());
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws InvalidKeyException {
        BigInteger n = keys.publicKey().modulus();
        byte[] wrapped = w.require(WRAPPED_KEY, ALG_ID);
        int blocks = Math.ceilDiv(DEK_BYTES, chunkBytes(n));
        if (wrapped.length != blocks * blockBytes(n)) {
            throw new InvalidKeyException("wrapped key is the wrong size to have been wrapped with " + ALG_ID);
        }
        var out = new ByteArrayOutputStream();
        for (int block = 0; block < blocks; block++) {
            int from = block * blockBytes(n);
            BigInteger c = new BigInteger(1, Arrays.copyOfRange(wrapped, from, from + blockBytes(n)));
            int chunk = Math.min(chunkBytes(n), DEK_BYTES - out.size());
            out.writeBytes(fixedWidth(c.modPow(keys.privateExponent(), n), chunk));
        }
        return new SecretKeySpec(out.toByteArray(), "AES");
    }

    /** The most bytes that are always numerically below the modulus. */
    private static int chunkBytes(BigInteger n) {
        return (n.bitLength() - 1) / 8;
    }

    private static int blockBytes(BigInteger n) {
        return (n.bitLength() + 7) / 8;
    }

    /** Big-endian, left-padded with zeros or trimmed of them, so every block has a known length. */
    private static byte[] fixedWidth(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }

    // No security at all, by design.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("pke", 0, 0, "keygen", "encrypt", "decrypt")
                .withParameterSet(String.valueOf(MODULUS_BITS)).withPadding("raw");
    }

    // No JCA provider: the arithmetic is written out by hand above.
    @Override
    public String provider() {
        return "none";
    }
}
