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
package com.callibrity.cryptoagility.cipher;

import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM: what this repo uses for data by default. It is also used inside the KEM-based
 * wrappers to wrap the data key under a key derived from the KEM.
 */
public final class AesGcm implements DataCipher {

  public static final AesGcm INSTANCE = new AesGcm();

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int TAG_BITS = 128;

  private AesGcm() {}

  @Override
  public String algId() {
    return "AES-256-GCM";
  }

  @Override
  public DataKeySpec keySpec() {
    return DataKeySpec.AES_256;
  }

  @Override
  public Encrypted encrypt(SecretKey dataKey, byte[] plaintext) throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.ENCRYPT_MODE, aes(dataKey)); // no nonce given, so the JDK picks a fresh one
    byte[] ciphertext = c.doFinal(plaintext);
    return new Encrypted(c.getIV(), ciphertext);
  }

  @Override
  public byte[] decrypt(SecretKey dataKey, byte[] nonce, byte[] ciphertext)
      throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.DECRYPT_MODE, aes(dataKey), new GCMParameterSpec(TAG_BITS, nonce));
    return c.doFinal(ciphertext);
  }

  /**
   * Wraps one key under another: the same cipher, used on a key instead of data. The tag also
   * covers the associated data, so unwrapping needs the same bytes again.
   */
  // The JDK's GCM does not take associated data in WRAP_MODE, so the key's bytes are encrypted
  // directly, and the copy taken here is wiped.
  public static Encrypted wrap(SecretKey kek, SecretKey key, byte[] aad)
      throws GeneralSecurityException {
    Objects.requireNonNull(aad, "aad");
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.ENCRYPT_MODE, aes(kek)); // no nonce given, so the JDK picks a fresh one
    c.updateAAD(aad);
    byte[] bytes = key.getEncoded();
    try {
      return new Encrypted(c.getIV(), c.doFinal(bytes));
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  /** Unwraps a key, failing unless the associated data is what it was wrapped with. */
  public static SecretKey unwrap(SecretKey kek, byte[] nonce, byte[] wrapped, byte[] aad)
      throws GeneralSecurityException {
    Objects.requireNonNull(aad, "aad");
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.DECRYPT_MODE, aes(kek), new GCMParameterSpec(TAG_BITS, nonce));
    c.updateAAD(aad);
    byte[] bytes = c.doFinal(wrapped);
    try {
      return new SecretKeySpec(bytes, "AES");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  // A key's bytes are what matter; this labels them as an AES key whatever they were called before.
  // SecretKeySpec keeps its own copy, so the copy taken here is wiped.
  private static SecretKey aes(SecretKey key) {
    if ("AES".equals(key.getAlgorithm())) {
      return key;
    }
    byte[] bytes = key.getEncoded();
    try {
      return new SecretKeySpec(bytes, "AES");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  @Override
  public AlgorithmFacts facts() {
    return AlgorithmFacts.of("ae", 256, 5, "keygen", "encrypt", "decrypt", "tag")
        .withParameterSet("256")
        .withMode("gcm")
        .withOid("2.16.840.1.101.3.4.1.46");
  }

  @Override
  public String provider() {
    try {
      return Cipher.getInstance(TRANSFORMATION).getProvider().getName();
    } catch (GeneralSecurityException _) {
      return "unavailable";
    }
  }
}
