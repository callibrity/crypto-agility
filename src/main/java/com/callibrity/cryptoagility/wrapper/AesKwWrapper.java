package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Inventoried;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Symmetric: an AES-256 key wraps the AES-256 data key (AES Key Wrap, RFC 3394).
 * This is what envelope encryption with a cloud KMS usually does. The wrapping
 * key lives in the KMS and never leaves it; only the small data key goes in to
 * be wrapped or unwrapped.
 *
 * <p>It is already quantum-safe. Grover's algorithm halves the strength of AES-256
 * to about 128 bits, which is still plenty. The catch is that it is symmetric:
 * whoever can wrap can also unwrap, so writer and reader must share the key.
 * Across a trust boundary you need public-key wrapping, and that is the part a
 * quantum computer breaks.
 */
public final class AesKwWrapper implements KeyWrapper, Inventoried {

    public static final String ALG_ID = "AES-256-KW";

    private static final String WRAPPED_KEY = "wrappedKey";
    private static final String TRANSFORMATION = "AES/KW/NoPadding";

    private final SecretKey kek;

    public AesKwWrapper() {
        this(newKey());
    }

    public AesKwWrapper(SecretKey kek) {
        this.kek = kek;
    }

    public static SecretKey newKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    @Override
    public String algId() { return ALG_ID; }

    @Override
    public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.WRAP_MODE, kek);
        return WrappedDek.of(WRAPPED_KEY, c.wrap(dek));
    }

    @Override
    public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.UNWRAP_MODE, kek);
        return (SecretKey) c.unwrap(w.require(WRAPPED_KEY, ALG_ID), "AES", Cipher.SECRET_KEY);
    }

    // NIST's category 5 is defined as being as hard to break as AES-256, so this is the top of the scale.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("block-cipher", 256, 5, "keygen", "encrypt", "decrypt")
                .withParameterSet("256").withMode("other").withOid("2.16.840.1.101.3.4.1.45");
    }

    @Override
    public String provider() {
        return Providers.names(() -> Cipher.getInstance(TRANSFORMATION).getProvider().getName());
    }
}
