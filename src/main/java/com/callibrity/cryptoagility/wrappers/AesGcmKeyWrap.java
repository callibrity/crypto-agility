package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * The second half of every KEM-based wrapper. A KEM hands you a shared secret,
 * not a way to encrypt a key you already have, so the data key is AES-GCM
 * wrapped under a key derived from that secret.
 */
final class AesGcmKeyWrap {

    private static final SecureRandom RNG = new SecureRandom();

    private AesGcmKeyWrap() {}

    static WrappedDek wrap(SecretKey kek, SecretKey dek, byte[] kemCt) throws GeneralSecurityException {
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, nonce));
        return new WrappedDek(c.wrap(dek), kemCt, nonce);
    }

    static SecretKey unwrap(SecretKey kek, WrappedDek w) throws GeneralSecurityException {
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, w.wrapNonce()));
        return (SecretKey) c.unwrap(w.wrappedKey(), "AES", Cipher.SECRET_KEY);
    }

    /** A wrapped key that never went through a KEM has nothing for a KEM-based wrapper to open. */
    static void requireKemFields(WrappedDek w, String algId) throws InvalidKeyException {
        if (w.kemCt() == null || w.wrapNonce() == null) {
            throw new InvalidKeyException("wrapped key has no KEM ciphertext, so it was not wrapped with " + algId);
        }
    }
}
