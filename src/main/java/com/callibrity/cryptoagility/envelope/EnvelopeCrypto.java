package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.cipher.Sealed;
import com.callibrity.cryptoagility.kms.DataKey;
import com.callibrity.cryptoagility.kms.KeyManagementService;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.wrapper.WrappedDek;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Envelope encryption against a KMS. The KMS hands out a fresh data key for
 * each record and keeps the key that wraps it; the data is encrypted here, in
 * the application, and never goes near the KMS.
 */
public final class EnvelopeCrypto {

    private EnvelopeCrypto() {}

    public static Envelope encrypt(byte[] plaintext, KeyManagementService kms, String keyId, DataCipher cipher)
            throws GeneralSecurityException, IOException {
        DataKey dataKey = kms.generateDataKey(keyId, cipher.keySpec());   // the only line that involves the KEK
        Sealed sealed = cipher.seal(dataKey.key(), plaintext);
        return new Envelope(dataKey.algorithm(), keyId, cipher.algId(),   // and the envelope says what it used
                sealed.nonce(), sealed.ciphertext(), dataKey.wrapped());
    }

    public static byte[] decrypt(Envelope env, KeyManagementService kms) throws GeneralSecurityException, IOException {
        DataCipher cipher = DataCiphers.get(env.enc());
        SecretKey dataKey = kms.decryptDataKey(keyIdOf(env, kms), env.wrappedDek());
        return cipher.open(dataKey, env.nonce(), env.ciphertext());
    }

    /**
     * Moves an envelope to another KMS key without touching the data. The KMS
     * re-wraps the data key internally; the nonce, ciphertext and data cipher
     * are carried over as they are.
     */
    public static Envelope rewrap(Envelope env, KeyManagementService kms, String newKeyId)
            throws GeneralSecurityException, IOException {
        WrappedDek moved = kms.reEncrypt(keyIdOf(env, kms), env.wrappedDek(), newKeyId);
        String algorithm = kms.describeKey(newKeyId).algorithm();
        return new Envelope(algorithm, newKeyId, env.enc(), env.nonce(), env.ciphertext(), moved);
    }

    // The key id says which key opens the data key. If the envelope also names an algorithm, it must agree.
    private static String keyIdOf(Envelope env, KeyManagementService kms) throws GeneralSecurityException, IOException {
        if (env.kid() == null) {
            throw new InvalidKeyException("the envelope names no key, so nothing says which key opens it");
        }
        KeyMetadata key = kms.describeKey(env.kid());
        if (env.alg() != null && !env.alg().equals(key.algorithm())) {
            throw new InvalidKeyException("the envelope says " + env.alg() + ", but key " + env.kid()
                    + " is " + key.algorithm());
        }
        return env.kid();
    }
}
