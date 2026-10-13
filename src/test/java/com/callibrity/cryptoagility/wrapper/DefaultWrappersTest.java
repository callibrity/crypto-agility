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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.callibrity.cryptoagility.cbom.Inventoried;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DefaultWrappersTest {

  private static final SecretKey DATA_KEY = new SecretKeySpec(new byte[32], "AES");
  private static final byte[] AAD = {1, 2, 3};

  // Each wrapper made with its no-argument constructor, which generates a fresh key.
  static List<KeyWrapper> wrappers() throws GeneralSecurityException {
    return List.of(
        new RsaWrapper(),
        new EcdhWrapper(),
        new AesGcmWrapper(),
        new MlKemWrapper(),
        new HybridWrapper(),
        new HqcWrapper());
  }

  @Nested
  class Made_with_a_fresh_key {

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.wrapper.DefaultWrappersTest#wrappers")
    void unwraps_what_it_wrapped(KeyWrapper wrapper) throws GeneralSecurityException {
      assertArrayEquals(
          DATA_KEY.getEncoded(), wrapper.unwrap(wrapper.wrap(DATA_KEY, AAD), AAD).getEncoded());
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.wrapper.DefaultWrappersTest#wrappers")
    void refuses_to_unwrap_with_other_associated_data(KeyWrapper wrapper)
        throws GeneralSecurityException {
      WrappedDek wrapped = wrapper.wrap(DATA_KEY, AAD);

      assertThrows(GeneralSecurityException.class, () -> wrapper.unwrap(wrapped, new byte[] {9}));
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.wrapper.DefaultWrappersTest#wrappers")
    void refuses_missing_associated_data(KeyWrapper wrapper) {
      assertThrows(NullPointerException.class, () -> wrapper.wrap(DATA_KEY, null));
    }

    @ParameterizedTest
    @MethodSource("com.callibrity.cryptoagility.wrapper.DefaultWrappersTest#wrappers")
    void describes_itself_and_finds_its_provider(KeyWrapper wrapper) {
      Inventoried described = (Inventoried) wrapper;

      assertNotNull(described.facts());
      assertNotEquals("unavailable", described.provider());
    }

    @Test
    void uses_the_usual_strengths() throws GeneralSecurityException {
      assertEquals("RSA-OAEP-3072", new RsaWrapper().algId());
      assertEquals("ECDH-X25519", new EcdhWrapper().algId());
      assertEquals("AES-256-GCMKW", new AesGcmWrapper().algId());
      assertEquals("ML-KEM-768", new MlKemWrapper(MlKemWrapper.newKeyPair()).algId());
      assertEquals("HQC-192", new HqcWrapper(HqcWrapper.newKeyPair()).algId());
    }
  }

  @Nested
  class Given_a_wrapped_key_missing_a_field {

    @Test
    void says_which_field_and_which_algorithm() {
      var wrapped = WrappedDek.of("wrappedKey", new byte[48]);

      var e = assertThrows(InvalidKeyException.class, () -> wrapped.require("kemCt", "ML-KEM-768"));

      assertTrue(e.getMessage().contains("no kemCt field"));
      assertTrue(e.getMessage().contains("ML-KEM-768"));
    }
  }

  @Nested
  class The_hybrid {

    private final SecretKey dataKey = new SecretKeySpec(new byte[32], "AES");

    // A copy of the wrapped key with the last byte of one field flipped.
    private WrappedDek tampered(WrappedDek wrapped, String field) {
      Map<String, byte[]> fields = new LinkedHashMap<>(wrapped.fields());
      byte[] bytes = fields.get(field).clone();
      bytes[bytes.length - 1] ^= 1;
      fields.put(field, bytes);
      return new WrappedDek(fields);
    }

    @Test
    void needs_the_classical_half_intact() throws GeneralSecurityException {
      var hybrid = new HybridWrapper();
      WrappedDek wrapped = hybrid.wrap(dataKey, AAD);

      assertThrows(
          GeneralSecurityException.class,
          () -> hybrid.unwrap(tampered(wrapped, "ephemeralKey"), AAD));
    }

    @Test
    void needs_the_post_quantum_half_intact() throws GeneralSecurityException {
      var hybrid = new HybridWrapper();
      WrappedDek wrapped = hybrid.wrap(dataKey, AAD);

      assertThrows(
          GeneralSecurityException.class, () -> hybrid.unwrap(tampered(wrapped, "kemCt"), AAD));
    }

    @Test
    void refuses_an_ml_kem_key_of_another_strength() throws GeneralSecurityException {
      var x25519 = HybridWrapper.newX25519KeyPair();
      var key1024 = MlKemWrapper.newKeyPair(MlKemWrapper.ParameterSet.ML_KEM_1024);

      assertThrows(InvalidKeyException.class, () -> new HybridWrapper(x25519, key1024));
    }
  }
}
