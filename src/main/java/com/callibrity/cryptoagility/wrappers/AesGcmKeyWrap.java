package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.WrappedDek;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The second half of every KEM-based wrapper. A KEM hands you a shared secret,
 * not a way to encrypt a key you already have, so the data key is AES-GCM
 * wrapped under a key derived from that secret.
 */
final class AesGcmKeyWrap {

    static final String WRAPPED_KEY = "wrappedKey";
    static final String WRAP_NONCE = "wrapNonce";

    private static final SecureRandom RNG = new SecureRandom();

    private AesGcmKeyWrap() {}

    /** Wraps the data key and returns it together with the fields the KEM needs to find the key again. */
    static WrappedDek wrap(SecretKey kek, SecretKey dek, Map<String, byte[]> kemFields) throws GeneralSecurityException {
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, nonce));
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put(WRAPPED_KEY, c.wrap(dek));
        fields.putAll(kemFields);
        fields.put(WRAP_NONCE, nonce);
        return new WrappedDek(fields);
    }

    static SecretKey unwrap(SecretKey kek, WrappedDek w, String algId) throws GeneralSecurityException {
        var c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, w.require(WRAP_NONCE, algId)));
        return (SecretKey) c.unwrap(w.require(WRAPPED_KEY, algId), "AES", Cipher.SECRET_KEY);
    }
}
