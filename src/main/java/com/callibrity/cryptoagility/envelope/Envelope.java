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
package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.cipher.Encrypted;
import com.callibrity.cryptoagility.kms.DataKey;
import com.callibrity.cryptoagility.kms.KeyManagementService;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKey;

/**
 * The stored envelope. Two layers, each named, using the same header names as JWE (JSON Web
 * Encryption):
 *
 * <ul>
 *   <li>alg and kid say how the data key was wrapped, and which KMS key opens it.
 *   <li>enc says which cipher encrypted the data with that data key.
 * </ul>
 *
 * <p>The names are what let old and new data live side by side: every envelope says how to open
 * itself, so nothing has to be migrated on the day the algorithm changes.
 *
 * <p>Sealing and opening happen here, in the application. The KMS hands out a fresh data key for
 * each envelope and keeps the key that wraps it; the data itself never goes near the KMS.
 */
public record Envelope(
    String alg, String kid, String enc, byte[] nonce, byte[] ciphertext, WrappedDek wrappedDek) {

  /** Encrypts the plaintext under a fresh data key from the KMS, and records what was used. */
  public static Envelope seal(
      byte[] plaintext, KeyManagementService kms, String keyId, DataCipher cipher)
      throws GeneralSecurityException, IOException {
    // The only line that involves the KEK.
    DataKey dataKey = kms.generateDataKey(keyId, cipher.keySpec());
    // The data never goes to the KMS.
    Encrypted encrypted = cipher.encrypt(dataKey.key(), plaintext);
    // And the envelope says what it used.
    return new Envelope(
        dataKey.algorithm(),
        keyId,
        cipher.algId(),
        encrypted.nonce(),
        encrypted.ciphertext(),
        dataKey.wrapped());
  }

  /** Asks the KMS to unwrap the data key, then decrypts the data here. */
  public byte[] open(KeyManagementService kms) throws GeneralSecurityException, IOException {
    DataCipher cipher = DataCiphers.get(enc);
    SecretKey dataKey = kms.decryptDataKey(checkedKeyId(kms), wrappedDek);
    return cipher.decrypt(dataKey, nonce, ciphertext);
  }

  /**
   * Moves this envelope to another KMS key without touching the data. The KMS re-wraps the data key
   * internally; the nonce, ciphertext and data cipher are carried over as they are.
   */
  public Envelope rewrap(KeyManagementService kms, String newKeyId)
      throws GeneralSecurityException, IOException {
    WrappedDek moved = kms.reEncrypt(checkedKeyId(kms), wrappedDek, newKeyId);
    String algorithm = kms.describeKey(newKeyId).algorithm();
    return new Envelope(algorithm, newKeyId, enc, nonce, ciphertext, moved);
  }

  // The key id says which key opens the data key. If the envelope also names an algorithm, it must
  // agree.
  private String checkedKeyId(KeyManagementService kms)
      throws GeneralSecurityException, IOException {
    if (kid == null) {
      throw new InvalidKeyException(
          "the envelope names no key, so nothing says which key opens it");
    }
    KeyMetadata key = kms.describeKey(kid);
    if (alg != null && !alg.equals(key.algorithm())) {
      throw new InvalidKeyException(
          "the envelope says " + alg + ", but key " + kid + " is " + key.algorithm());
    }
    return kid;
  }

  /** A one-line description for printing; the raw bytes are abbreviated. */
  public String summary() {
    var out =
        new StringBuilder("{alg=")
            .append(alg)
            .append(", kid=")
            .append(kid)
            .append(", enc=")
            .append(enc)
            .append(", ciphertext=")
            .append(Base64.getEncoder().encodeToString(ciphertext), 0, 16)
            .append("...");
    wrappedDek
        .fields()
        .forEach(
            (name, value) ->
                out.append(", ").append(name).append('=').append(value.length).append(" bytes"));
    return out.append('}').toString();
  }

  // Records compare arrays by identity, so equality and hashing are spelled out to compare their
  // bytes.
  @Override
  public boolean equals(Object other) {
    return other
            instanceof
            Envelope(
                String alg1,
                String kid1,
                String enc1,
                byte[] nonce1,
                byte[] ciphertext1,
                WrappedDek dek)
        && Objects.equals(alg, alg1)
        && Objects.equals(kid, kid1)
        && Objects.equals(enc, enc1)
        && Arrays.equals(nonce, nonce1)
        && Arrays.equals(ciphertext, ciphertext1)
        && Objects.equals(wrappedDek, dek);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        alg, kid, enc, Arrays.hashCode(nonce), Arrays.hashCode(ciphertext), wrappedDek);
  }

  /** The names and sizes, never the bytes themselves. */
  @Override
  public String toString() {
    return "Envelope[alg="
        + alg
        + ", kid="
        + kid
        + ", enc="
        + enc
        + ", nonce="
        + size(nonce)
        + ", ciphertext="
        + size(ciphertext)
        + ", wrappedDek="
        + wrappedDek
        + "]";
  }

  private static String size(byte[] bytes) {
    return bytes == null ? "null" : bytes.length + " bytes";
  }
}
