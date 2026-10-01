package com.callibrity.cryptoagility.envelope;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Envelope encryption in plain JCA. The data is ALWAYS AES-256-GCM (quantum is
 * fine with that). The only algorithm-dependent step is how the data key (DEK)
 * gets wrapped, and that is delegated to a KeyWrapper.
 */
public final class EnvelopeCrypto {

    private static final SecureRandom RNG = new SecureRandom();

    private EnvelopeCrypto() {}

    public static Envelope encrypt(byte[] plaintext, KeyWrapper wrapper) throws GeneralSecurityException {
        var kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey dek = kg.generateKey();
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(128, nonce));
        byte[] ct = c.doFinal(plaintext);
        WrappedDek w = wrapper.wrap(dek);                        // the only algorithm-dependent line
        return new Envelope(wrapper.algId(), nonce, ct, w.wrappedKey(), w.kemCt(), w.wrapNonce());
    }

    public static byte[] decrypt(Envelope env, WrapperRegistry registry) throws GeneralSecurityException {
        KeyWrapper wrapper = registry.get(env.alg());            // each envelope names its own algorithm
        SecretKey dek = wrapper.unwrap(env.wrappedDek());
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(128, env.nonce()));
        return c.doFinal(env.ciphertext());
    }

    /**
     * Moves an envelope to a new wrapping algorithm without touching the data.
     * Only the 32-byte data key is unwrapped and wrapped again; the nonce and
     * ciphertext are carried over as they are.
     */
    public static Envelope rewrap(Envelope env, WrapperRegistry registry, KeyWrapper target)
            throws GeneralSecurityException {
        SecretKey dek = registry.get(env.alg()).unwrap(env.wrappedDek());
        WrappedDek w = target.wrap(dek);
        return new Envelope(target.algId(), env.nonce(), env.ciphertext(), w.wrappedKey(), w.kemCt(), w.wrapNonce());
    }
}
