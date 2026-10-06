package com.callibrity.cryptoagility.cipher;

import com.callibrity.cryptoagility.envelope.Inventoried;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * Encrypts the data itself with the data key. This is the other layer of the
 * envelope: KeyWrapper protects the data key, DataCipher protects the data.
 * Quantum computers do not threaten either cipher here, so this rarely needs to
 * change, but each envelope still records which one it used.
 */
public interface DataCipher extends Inventoried {

    /** The name written into every envelope that uses this cipher. */
    String algId();

    /** The data key this cipher needs, for asking the KMS to generate one. */
    DataKeySpec keySpec();

    /**
     * Encrypts and returns the ciphertext with its nonce. Implementations let
     * the JDK choose a fresh random nonce, so no caller can ever reuse one: with
     * AES-GCM and ChaCha20-Poly1305, using a nonce twice under the same key is
     * a disaster.
     */
    Encrypted encrypt(SecretKey dataKey, byte[] plaintext) throws GeneralSecurityException;

    byte[] decrypt(SecretKey dataKey, byte[] nonce, byte[] ciphertext) throws GeneralSecurityException;
}
