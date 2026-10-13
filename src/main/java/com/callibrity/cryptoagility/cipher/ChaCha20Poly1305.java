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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 (RFC 8439), built into the JDK since 11. The usual alternative to AES-GCM: as
 * strong, and faster on hardware without AES instructions. Adding it took this class and one line
 * in DataCiphers.
 */
public final class ChaCha20Poly1305 implements DataCipher {

  public static final ChaCha20Poly1305 INSTANCE = new ChaCha20Poly1305();

  // Written out in full: it is an authenticated stream cipher, so it has no block mode and needs no
  // padding.
  private static final String TRANSFORMATION = "ChaCha20-Poly1305/None/NoPadding";

  private ChaCha20Poly1305() {}

  @Override
  public String algId() {
    return "ChaCha20-Poly1305";
  }

  @Override
  public DataKeySpec keySpec() {
    return DataKeySpec.CHACHA20;
  }

  @Override
  public Encrypted encrypt(SecretKey dataKey, byte[] plaintext) throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.ENCRYPT_MODE, chacha(dataKey)); // no nonce given, so the JDK picks a fresh one
    byte[] ciphertext = c.doFinal(plaintext);
    return new Encrypted(c.getIV(), ciphertext);
  }

  @Override
  public byte[] decrypt(SecretKey dataKey, byte[] nonce, byte[] ciphertext)
      throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.DECRYPT_MODE, chacha(dataKey), new IvParameterSpec(nonce));
    return c.doFinal(ciphertext);
  }

  // The JDK insists the key is labelled ChaCha20; a data key comes back from the KMS as plain
  // bytes. SecretKeySpec keeps its own copy, so the copy taken here is wiped.
  private static SecretKey chacha(SecretKey key) {
    if ("ChaCha20".equals(key.getAlgorithm())) {
      return key;
    }
    byte[] bytes = key.getEncoded();
    try {
      return new SecretKeySpec(bytes, "ChaCha20");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  // A 256-bit key, so the same Grover argument as AES-256 puts it at the top of NIST's scale.
  @Override
  public AlgorithmFacts facts() {
    return AlgorithmFacts.of("ae", 256, 5, "keygen", "encrypt", "decrypt", "tag")
        .withParameterSet("256")
        .withOid("1.2.840.113549.1.9.16.3.18");
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
