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

import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import com.callibrity.cryptoagility.cbom.Inventoried;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Symmetric: an AES-256 key wraps the AES-256 data key with AES-GCM. This is what envelope
 * encryption with a cloud KMS usually does (AWS KMS and Google Cloud KMS both wrap with
 * AES-256-GCM). The wrapping key lives in the KMS and never leaves it; only the small data key goes
 * in to be wrapped or unwrapped.
 *
 * <p>It is already quantum-safe. Grover's algorithm halves the strength of AES-256 to about 128
 * bits, which is still plenty. The catch is that it is symmetric: whoever can wrap can also unwrap,
 * so writer and reader must share the key. Across a trust boundary you need public-key wrapping,
 * and that is the part a quantum computer breaks.
 */
public final class AesGcmWrapper implements KeyWrapper, Inventoried {

  public static final String ALG_ID = "AES-256-GCMKW";

  private final SecretKey kek;

  public AesGcmWrapper() {
    this(newKey());
  }

  public AesGcmWrapper(SecretKey kek) {
    this.kek = kek;
  }

  public static SecretKey newKey() {
    byte[] key = new byte[32];
    try {
      new SecureRandom().nextBytes(key);
      return new SecretKeySpec(key, "AES");
    } finally {
      // SecretKeySpec keeps its own copy; this one is wiped.
      Arrays.fill(key, (byte) 0);
    }
  }

  @Override
  public String algId() {
    return ALG_ID;
  }

  @Override
  public WrappedDek wrap(SecretKey dek, byte[] aad) throws GeneralSecurityException {
    return AesGcmKeyWrap.wrap(kek, dek, Map.of(), aad);
  }

  @Override
  public SecretKey unwrap(WrappedDek w, byte[] aad) throws GeneralSecurityException {
    return AesGcmKeyWrap.unwrap(kek, w, ALG_ID, aad);
  }

  // NIST's category 5 is defined as being as hard to break as AES-256, so this is the top of the
  // scale.
  @Override
  public AlgorithmFacts facts() {
    return AlgorithmFacts.of("ae", 256, 5, "keygen", "encrypt", "decrypt", "tag")
        .withParameterSet("256")
        .withMode("gcm")
        .withOid("2.16.840.1.101.3.4.1.46");
  }

  @Override
  public String provider() {
    return Providers.names(() -> Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
  }
}
