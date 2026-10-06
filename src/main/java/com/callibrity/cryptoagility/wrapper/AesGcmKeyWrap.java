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
package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.cipher.AesGcm;
import com.callibrity.cryptoagility.cipher.Encrypted;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.SecretKey;

/**
 * The second half of every KEM-based wrapper. A KEM hands you a shared secret, not a way to encrypt
 * a key you already have, so the data key is AES-GCM wrapped under a key derived from that secret.
 */
final class AesGcmKeyWrap {

  static final String WRAPPED_KEY = "wrappedKey";
  static final String WRAP_NONCE = "wrapNonce";

  private AesGcmKeyWrap() {}

  /**
   * Wraps the data key and returns it together with the fields the KEM needs to find the key again.
   */
  static WrappedDek wrap(SecretKey kek, SecretKey dek, Map<String, byte[]> kemFields)
      throws GeneralSecurityException {
    Encrypted encrypted = AesGcm.wrap(kek, dek);
    Map<String, byte[]> fields = new LinkedHashMap<>();
    fields.put(WRAPPED_KEY, encrypted.ciphertext());
    fields.putAll(kemFields);
    fields.put(WRAP_NONCE, encrypted.nonce());
    return new WrappedDek(fields);
  }

  static SecretKey unwrap(SecretKey kek, WrappedDek w, String algId)
      throws GeneralSecurityException {
    return AesGcm.unwrap(kek, w.require(WRAP_NONCE, algId), w.require(WRAPPED_KEY, algId));
  }
}
