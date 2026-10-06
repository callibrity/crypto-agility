package com.callibrity.cryptoagility.cipher;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES-256-GCM: what this repo uses for data by default. It is also used inside
 * the KEM-based wrappers to wrap the data key under a key derived from the KEM.
 */
public final class AesGcm implements DataCipher {

    public static final AesGcm INSTANCE = new AesGcm();

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;

    private AesGcm() {}

    @Override
    public String algId() { return "AES-256-GCM"; }

    @Override
    public DataKeySpec keySpec() { return DataKeySpec.AES_256; }

    @Override
    public Encrypted encrypt(SecretKey dataKey, byte[] plaintext) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, aes(dataKey));                // no nonce given, so the JDK picks a fresh one
        byte[] ciphertext = c.doFinal(plaintext);
        return new Encrypted(c.getIV(), ciphertext);
    }

    @Override
    public byte[] decrypt(SecretKey dataKey, byte[] nonce, byte[] ciphertext) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, aes(dataKey), new GCMParameterSpec(TAG_BITS, nonce));
        return c.doFinal(ciphertext);
    }

    /** Wraps one key under another: the same cipher, used on a key instead of data. */
    public static Encrypted wrap(SecretKey kek, SecretKey key) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.WRAP_MODE, aes(kek));                       // no nonce given, so the JDK picks a fresh one
        byte[] wrapped = c.wrap(key);
        return new Encrypted(c.getIV(), wrapped);
    }

    public static SecretKey unwrap(SecretKey kek, byte[] nonce, byte[] wrapped) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.UNWRAP_MODE, aes(kek), new GCMParameterSpec(TAG_BITS, nonce));
        return (SecretKey) c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    // A key's bytes are what matter; this labels them as an AES key whatever they were called before.
    private static SecretKey aes(SecretKey key) {
        return "AES".equals(key.getAlgorithm()) ? key : new SecretKeySpec(key.getEncoded(), "AES");
    }

    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("ae", 256, 5, "keygen", "encrypt", "decrypt", "tag")
                .withParameterSet("256").withMode("gcm").withOid("2.16.840.1.101.3.4.1.46");
    }

    @Override
    public String provider() {
        try {
            return Cipher.getInstance(TRANSFORMATION).getProvider().getName();
        } catch (GeneralSecurityException _) {
            return "unavailable";
        }
    }
}
