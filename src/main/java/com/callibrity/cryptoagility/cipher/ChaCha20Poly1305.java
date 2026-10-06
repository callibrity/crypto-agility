package com.callibrity.cryptoagility.cipher;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * ChaCha20-Poly1305 (RFC 8439), built into the JDK since 11. The usual
 * alternative to AES-GCM: as strong, and faster on hardware without AES
 * instructions. Adding it took this class and one line in DataCiphers.
 */
public final class ChaCha20Poly1305 implements DataCipher {

    public static final ChaCha20Poly1305 INSTANCE = new ChaCha20Poly1305();

    // Written out in full: it is an authenticated stream cipher, so it has no block mode and needs no padding.
    private static final String TRANSFORMATION = "ChaCha20-Poly1305/None/NoPadding";

    private ChaCha20Poly1305() {}

    @Override
    public String algId() { return "ChaCha20-Poly1305"; }

    @Override
    public DataKeySpec keySpec() { return DataKeySpec.CHACHA20; }

    @Override
    public Encrypted encrypt(SecretKey dataKey, byte[] plaintext) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, chacha(dataKey));             // no nonce given, so the JDK picks a fresh one
        byte[] ciphertext = c.doFinal(plaintext);
        return new Encrypted(c.getIV(), ciphertext);
    }

    @Override
    public byte[] decrypt(SecretKey dataKey, byte[] nonce, byte[] ciphertext) throws GeneralSecurityException {
        var c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, chacha(dataKey), new IvParameterSpec(nonce));
        return c.doFinal(ciphertext);
    }

    // The JDK insists the key is labelled ChaCha20; a data key comes back from the KMS as plain bytes.
    private static SecretKey chacha(SecretKey key) {
        return "ChaCha20".equals(key.getAlgorithm()) ? key : new SecretKeySpec(key.getEncoded(), "ChaCha20");
    }

    // A 256-bit key, so the same Grover argument as AES-256 puts it at the top of NIST's scale.
    @Override
    public AlgorithmFacts facts() {
        return AlgorithmFacts.of("ae", 256, 5, "keygen", "encrypt", "decrypt", "tag")
                .withParameterSet("256").withOid("1.2.840.113549.1.9.16.3.18");
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
