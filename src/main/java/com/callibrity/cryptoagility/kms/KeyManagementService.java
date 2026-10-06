/*
 * Copyright © 2026 Callibrity, Inc. (contactus@callibrity.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.cipher.DataKeySpec;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.crypto.SecretKey;

/**
 * A key management service, in the shape of the real ones (AWS KMS, Google Cloud KMS, Azure Key
 * Vault). The application never holds a key-encrypting key. It names one by id and asks the service
 * to work with it:
 *
 * <ul>
 *   <li>generateDataKey hands back a fresh data key, in plaintext to use once and wrapped to store
 *       (AWS calls it GenerateDataKey).
 *   <li>decryptDataKey turns a stored wrapped key back into a data key (Decrypt).
 *   <li>reEncrypt moves a wrapped key to another key without the plaintext data key ever leaving
 *       the service (ReEncrypt).
 * </ul>
 *
 * <p>The data itself never goes to the KMS. It is encrypted and decrypted in the application, with
 * the data key.
 *
 * <p>LocalKms is a stand-in that keeps its keys in files. A class talking to a real KMS would
 * implement this same interface, and nothing else would change.
 */
public interface KeyManagementService {

  /** The key-encrypting algorithms this KMS can create keys for. */
  List<String> algorithms();

  AlgorithmInfo describeAlgorithm(String algorithm) throws GeneralSecurityException;

  KeyMetadata createKey(String algorithm) throws GeneralSecurityException, IOException;

  KeyMetadata describeKey(String keyId) throws GeneralSecurityException, IOException;

  List<KeyMetadata> listKeys() throws IOException;

  DataKey generateDataKey(String keyId, DataKeySpec spec)
      throws GeneralSecurityException, IOException;

  SecretKey decryptDataKey(String keyId, WrappedDek wrapped)
      throws GeneralSecurityException, IOException;

  WrappedDek reEncrypt(String keyId, WrappedDek wrapped, String newKeyId)
      throws GeneralSecurityException, IOException;

  void disableKey(String keyId) throws GeneralSecurityException, IOException;

  void enableKey(String keyId) throws GeneralSecurityException, IOException;
}
