package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.cipher.DataKeySpec;
import com.callibrity.cryptoagility.wrapper.WrappedDek;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * A key management service, in the shape of the real ones (AWS KMS, Google
 * Cloud KMS, Azure Key Vault). The application never holds a key-encrypting
 * key. It names one by id and asks the service to work with it:
 *
 * <ul>
 *   <li>generateDataKey hands back a fresh data key, in plaintext to use once and
 *     wrapped to store (AWS calls it GenerateDataKey).
 *   <li>decryptDataKey turns a stored wrapped key back into a data key (Decrypt).
 *   <li>reEncrypt moves a wrapped key to another key without the plaintext data
 *     key ever leaving the service (ReEncrypt).
 * </ul>
 *
 * <p>The data itself never goes to the KMS. It is encrypted and decrypted in the
 * application, with the data key.
 *
 * <p>LocalKms is a stand-in that keeps its keys in files. A class talking to a
 * real KMS would implement this same interface, and nothing else would change.
 */
public interface KeyManagementService {

    /** The key-encrypting algorithms this KMS can create keys for. */
    List<String> algorithms();

    AlgorithmInfo describeAlgorithm(String algorithm) throws GeneralSecurityException;

    KeyMetadata createKey(String algorithm) throws GeneralSecurityException, IOException;

    KeyMetadata describeKey(String keyId) throws GeneralSecurityException, IOException;

    List<KeyMetadata> listKeys() throws IOException;

    DataKey generateDataKey(String keyId, DataKeySpec spec) throws GeneralSecurityException, IOException;

    SecretKey decryptDataKey(String keyId, WrappedDek wrapped) throws GeneralSecurityException, IOException;

    WrappedDek reEncrypt(String keyId, WrappedDek wrapped, String newKeyId) throws GeneralSecurityException, IOException;

    void disableKey(String keyId) throws GeneralSecurityException, IOException;

    void enableKey(String keyId) throws GeneralSecurityException, IOException;
}
