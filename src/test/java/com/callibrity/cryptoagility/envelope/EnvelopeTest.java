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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.callibrity.cryptoagility.cipher.AesGcm;
import com.callibrity.cryptoagility.cipher.ChaCha20Poly1305;
import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.kms.KeyDisabledException;
import com.callibrity.cryptoagility.kms.LocalKms;
import com.callibrity.cryptoagility.wrapper.MlKemWrapper;
import com.callibrity.cryptoagility.wrapper.RsaWrapper;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeTest {

  private static final byte[] PLAINTEXT = "customer record #1".getBytes(UTF_8);

  @TempDir Path dir;

  private LocalKms kms;
  private String rsaKey;
  private String mlKemKey;

  @BeforeEach
  void create_two_keys() throws GeneralSecurityException, IOException {
    kms = LocalKms.withStandardAlgorithms(dir);
    rsaKey = kms.createKey(RsaWrapper.ALG_ID).keyId();
    mlKemKey = kms.createKey(MlKemWrapper.ParameterSet.ML_KEM_768.algId()).keyId();
  }

  private static final WrappedDek WRAPPED_KEY = WrappedDek.of("wrappedKey", new byte[] {7, 7});

  private static Envelope envelope(String alg, byte ciphertextByte) {
    return new Envelope(
        alg,
        "key-000001",
        "AES-256-GCM",
        new byte[] {1, 2},
        new byte[] {ciphertextByte},
        WRAPPED_KEY);
  }

  @Nested
  class When_sealing {

    @Test
    void the_envelope_names_the_wrap_algorithm_the_key_and_the_data_cipher()
        throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, mlKemKey, AesGcm.INSTANCE);

      assertEquals("ML-KEM-768", env.alg());
      assertEquals(mlKemKey, env.kid());
      assertEquals("AES-256-GCM", env.enc());
    }

    @Test
    void either_data_cipher_round_trips() throws GeneralSecurityException, IOException {
      for (DataCipher cipher : DataCiphers.all()) {
        Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, cipher);

        assertEquals(cipher.algId(), env.enc());
        assertArrayEquals(PLAINTEXT, env.open(kms));
      }
    }

    @Test
    void tampered_ciphertext_is_rejected() throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
      byte[] ciphertext = env.ciphertext();
      ciphertext[0] ^= 1;
      var tampered =
          new Envelope(env.alg(), env.kid(), env.enc(), env.nonce(), ciphertext, env.wrappedDek());

      assertThrows(AEADBadTagException.class, () -> tampered.open(kms));
    }
  }

  @Nested
  class When_the_algorithm_changes {

    @Test
    void old_and_new_envelopes_open_side_by_side() throws GeneralSecurityException, IOException {
      Envelope old =
          Envelope.seal("written last year".getBytes(UTF_8), kms, rsaKey, AesGcm.INSTANCE);
      Envelope current =
          Envelope.seal("written today".getBytes(UTF_8), kms, mlKemKey, ChaCha20Poly1305.INSTANCE);

      assertEquals("written last year", new String(old.open(kms), UTF_8));
      assertEquals("written today", new String(current.open(kms), UTF_8));
    }
  }

  @Nested
  class When_rewrapping {

    @Test
    void the_nonce_ciphertext_and_data_cipher_are_untouched()
        throws GeneralSecurityException, IOException {
      Envelope before = Envelope.seal(PLAINTEXT, kms, rsaKey, ChaCha20Poly1305.INSTANCE);

      Envelope after = before.rewrap(kms, mlKemKey);

      assertArrayEquals(before.nonce(), after.nonce());
      assertArrayEquals(before.ciphertext(), after.ciphertext());
      assertEquals(before.enc(), after.enc());
    }

    @Test
    void the_envelope_names_the_new_key_and_algorithm()
        throws GeneralSecurityException, IOException {
      Envelope after = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE).rewrap(kms, mlKemKey);

      assertEquals("ML-KEM-768", after.alg());
      assertEquals(mlKemKey, after.kid());
    }

    @Test
    void it_still_opens_after_the_old_key_is_disabled()
        throws GeneralSecurityException, IOException {
      Envelope after = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE).rewrap(kms, mlKemKey);

      kms.disableKey(rsaKey);

      assertArrayEquals(PLAINTEXT, after.open(kms));
    }
  }

  @Nested
  class When_something_is_wrong {

    @Test
    void a_disabled_key_cannot_open_its_envelopes() throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);

      kms.disableKey(rsaKey);

      assertThrows(KeyDisabledException.class, () -> env.open(kms));
    }

    @Test
    void an_alg_that_does_not_match_the_key_is_caught()
        throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
      var forged =
          new Envelope(
              "ML-KEM-768", env.kid(), env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

      var e = assertThrows(InvalidKeyException.class, () -> forged.open(kms));

      assertTrue(e.getMessage().contains("is RSA-OAEP-3072"));
    }

    @Test
    void an_envelope_with_no_key_id_cannot_be_opened()
        throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
      var anonymous =
          new Envelope(env.alg(), null, env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

      assertThrows(InvalidKeyException.class, () -> anonymous.open(kms));
    }

    @Test
    void a_kid_pointed_at_another_key_of_the_same_algorithm_cannot_open_it()
        throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
      String otherRsaKey = kms.createKey(RsaWrapper.ALG_ID).keyId();
      var redirected =
          new Envelope(
              env.alg(), otherRsaKey, env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

      assertThrows(GeneralSecurityException.class, () -> redirected.open(kms));
    }

    @Test
    void an_unknown_data_cipher_is_named() throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
      var odd =
          new Envelope(
              env.alg(), env.kid(), "ROT13", env.nonce(), env.ciphertext(), env.wrappedDek());

      var e = assertThrows(UnknownAlgorithmException.class, () -> odd.open(kms));

      assertTrue(e.getMessage().contains("ROT13"));
    }
  }

  @Nested
  class When_the_header_is_changed {

    @Test
    void a_different_data_cipher_is_refused_when_the_data_key_is_unwrapped()
        throws GeneralSecurityException, IOException {
      Envelope env = Envelope.seal(PLAINTEXT, kms, mlKemKey, AesGcm.INSTANCE);
      byte[] claimsChaCha =
          Envelope.encryptionContext(env.alg(), env.kid(), ChaCha20Poly1305.INSTANCE.algId());

      assertThrows(
          AEADBadTagException.class,
          () -> kms.decryptDataKey(env.kid(), env.wrappedDek(), claimsChaCha));
    }

    @Test
    void an_envelope_whose_alg_was_removed_no_longer_opens()
        throws GeneralSecurityException, IOException {
      for (String keyId : new String[] {rsaKey, mlKemKey}) {
        Envelope env = Envelope.seal(PLAINTEXT, kms, keyId, AesGcm.INSTANCE);
        var unlabelled =
            new Envelope(
                null, env.kid(), env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

        assertThrows(GeneralSecurityException.class, () -> unlabelled.open(kms));
      }
    }

    @Test
    void a_rewrapped_envelope_is_bound_to_its_new_header()
        throws GeneralSecurityException, IOException {
      Envelope before = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);

      Envelope after = before.rewrap(kms, mlKemKey);
      var oldHeader =
          new Envelope(
              before.alg(),
              before.kid(),
              after.enc(),
              after.nonce(),
              after.ciphertext(),
              after.wrappedDek());

      assertArrayEquals(PLAINTEXT, after.open(kms));
      assertThrows(GeneralSecurityException.class, () -> oldHeader.open(kms));
    }
  }

  @Nested
  class Its_encryption_context {

    @Test
    void tells_a_missing_name_from_an_empty_one() {
      assertFalse(
          Arrays.equals(
              Envelope.encryptionContext(null, "key-000001", "AES-256-GCM"),
              Envelope.encryptionContext("", "key-000001", "AES-256-GCM")));
    }

    @Test
    void cannot_be_matched_by_moving_text_between_names() {
      assertFalse(
          Arrays.equals(
              Envelope.encryptionContext("ab", "c", "AES-256-GCM"),
              Envelope.encryptionContext("a", "bc", "AES-256-GCM")));
    }
  }

  @Nested
  class Guarding_its_bytes {

    @Test
    void changing_the_arrays_it_was_given_does_not_change_it() {
      byte[] nonce = {1, 2};
      byte[] ciphertext = {3, 4};
      var env =
          new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", nonce, ciphertext, WRAPPED_KEY);

      nonce[0] = 9;
      ciphertext[0] = 9;

      assertArrayEquals(new byte[] {1, 2}, env.nonce());
      assertArrayEquals(new byte[] {3, 4}, env.ciphertext());
    }

    @Test
    void changing_the_arrays_it_hands_out_does_not_change_it() {
      Envelope env = envelope("ML-KEM-768", (byte) 5);

      env.nonce()[0] = 9;
      env.ciphertext()[0] = 9;

      assertEquals(envelope("ML-KEM-768", (byte) 5), env);
    }

    @Test
    void refuses_a_missing_nonce_ciphertext_or_wrapped_key() {
      byte[] bytes = {1};

      assertThrows(
          NullPointerException.class,
          () -> new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", null, bytes, WRAPPED_KEY));
      assertThrows(
          NullPointerException.class,
          () -> new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", bytes, null, WRAPPED_KEY));
      assertThrows(
          NullPointerException.class,
          () -> new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", bytes, bytes, null));
    }
  }

  @Nested
  class Comparing {

    @Test
    void equal_contents_make_equal_envelopes() {
      assertEquals(envelope("ML-KEM-768", (byte) 5), envelope("ML-KEM-768", (byte) 5));
      assertEquals(
          envelope("ML-KEM-768", (byte) 5).hashCode(), envelope("ML-KEM-768", (byte) 5).hashCode());
    }

    @Test
    void a_different_header_or_different_bytes_make_a_different_envelope() {
      assertNotEquals(envelope("ML-KEM-768", (byte) 5), envelope("RSA-OAEP-3072", (byte) 5));
      assertNotEquals(envelope("ML-KEM-768", (byte) 5), envelope("ML-KEM-768", (byte) 6));
    }
  }

  @Nested
  class Comparing_wrapped_keys {

    @Test
    void compares_field_names_and_bytes_in_any_order() {
      Map<String, byte[]> first = new LinkedHashMap<>();
      first.put("wrappedKey", new byte[] {1});
      first.put("kemCt", new byte[] {2});
      Map<String, byte[]> second = new LinkedHashMap<>();
      second.put("kemCt", new byte[] {2});
      second.put("wrappedKey", new byte[] {1});

      assertEquals(new WrappedDek(first), new WrappedDek(second));
      assertEquals(new WrappedDek(first).hashCode(), new WrappedDek(second).hashCode());
      assertNotEquals(new WrappedDek(first), WrappedDek.of("wrappedKey", new byte[] {1}));
      assertNotEquals(
          WrappedDek.of("wrappedKey", new byte[] {1}), WrappedDek.of("wrappedKey", new byte[] {9}));
    }
  }

  @Nested
  class Printing {

    @Test
    void shows_names_and_sizes_but_never_the_bytes() {
      String text =
          new Envelope(
                  "ML-KEM-768",
                  "key-000001",
                  "AES-256-GCM",
                  new byte[12],
                  new byte[] {42, 42},
                  WrappedDek.of("wrappedKey", new byte[] {42}))
              .toString();

      assertTrue(text.contains("alg=ML-KEM-768"));
      assertTrue(text.contains("ciphertext=2 bytes"));
      assertTrue(text.contains("wrappedKey=1 bytes"));
      assertFalse(text.contains("42"));
    }
  }
}
