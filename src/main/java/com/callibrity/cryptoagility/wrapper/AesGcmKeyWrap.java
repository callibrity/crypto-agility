package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.cipher.AesGcm;
import com.callibrity.cryptoagility.cipher.Sealed;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
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

    private AesGcmKeyWrap() {}

    /** Wraps the data key and returns it together with the fields the KEM needs to find the key again. */
    static WrappedDek wrap(SecretKey kek, SecretKey dek, Map<String, byte[]> kemFields) throws GeneralSecurityException {
        Sealed sealed = AesGcm.wrap(kek, dek);
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put(WRAPPED_KEY, sealed.ciphertext());
        fields.putAll(kemFields);
        fields.put(WRAP_NONCE, sealed.nonce());
        return new WrappedDek(fields);
    }

    static SecretKey unwrap(SecretKey kek, WrappedDek w, String algId) throws GeneralSecurityException {
        return AesGcm.unwrap(kek, w.require(WRAP_NONCE, algId), w.require(WRAPPED_KEY, algId));
    }
}
