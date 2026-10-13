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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DataCiphersTest {

  private static final byte[] PLAINTEXT = "customer record #1".getBytes(UTF_8);

  static List<DataCipher> ciphers() {
    return DataCiphers.all();
  }

  // A data key as the KMS hands it back: the right number of bytes, whatever the label.
  private static SecretKey keyFor(DataCipher cipher) {
    byte[] bytes = new byte[cipher.keySpec().bytes()];
    new SecureRandom().nextBytes(bytes);
    return new SecretKeySpec(bytes, "RAW");
  }

  @Nested
  class For_each_cipher {

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.cipher.DataCiphersTest#ciphers")
    void decrypts_what_it_encrypted(DataCipher cipher) throws GeneralSecurityException {
      SecretKey key = keyFor(cipher);

      Encrypted encrypted = cipher.encrypt(key, PLAINTEXT);

      assertArrayEquals(PLAINTEXT, cipher.decrypt(key, encrypted.nonce(), encrypted.ciphertext()));
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.cipher.DataCiphersTest#ciphers")
    void chooses_a_fresh_nonce_every_time(DataCipher cipher) throws GeneralSecurityException {
      SecretKey key = keyFor(cipher);

      Encrypted first = cipher.encrypt(key, PLAINTEXT);
      Encrypted second = cipher.encrypt(key, PLAINTEXT);

      assertEquals(12, first.nonce().length);
      assertFalse(Arrays.equals(first.nonce(), second.nonce()));
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.cipher.DataCiphersTest#ciphers")
    void rejects_tampered_ciphertext(DataCipher cipher) throws GeneralSecurityException {
      SecretKey key = keyFor(cipher);
      Encrypted encrypted = cipher.encrypt(key, PLAINTEXT);
      byte[] tampered = encrypted.ciphertext();
      tampered[0] ^= 1;

      assertThrows(
          AEADBadTagException.class, () -> cipher.decrypt(key, encrypted.nonce(), tampered));
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.cipher.DataCiphersTest#ciphers")
    void is_served_by_the_jdk(DataCipher cipher) {
      assertEquals("SunJCE", cipher.provider());
    }
  }

  @Nested
  class Looking_one_up {

    @Test
    void aes_gcm_is_the_default() {
      assertSame(AesGcm.INSTANCE, DataCiphers.DEFAULT);
    }

    @Test
    void finds_chacha_by_the_name_envelopes_carry() throws UnknownAlgorithmException {
      assertSame(ChaCha20Poly1305.INSTANCE, DataCiphers.get("ChaCha20-Poly1305"));
    }

    @Test
    void an_unknown_name_is_refused() {
      assertThrows(UnknownAlgorithmException.class, () -> DataCiphers.get("ROT13"));
    }
  }
}
