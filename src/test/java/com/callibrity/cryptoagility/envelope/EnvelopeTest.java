package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.cipher.AesGcm;
import com.callibrity.cryptoagility.cipher.ChaCha20Poly1305;
import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.kms.KeyDisabledException;
import com.callibrity.cryptoagility.kms.LocalKms;
import com.callibrity.cryptoagility.wrapper.MlKemWrapper;
import com.callibrity.cryptoagility.wrapper.RsaWrapper;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.AEADBadTagException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeTest {

    private static final byte[] PLAINTEXT = "customer record #1".getBytes(UTF_8);

    @TempDir
    Path dir;

    private LocalKms kms;
    private String rsaKey;
    private String mlKemKey;

    @BeforeEach
    void create_two_keys() throws GeneralSecurityException, IOException {
        kms = LocalKms.withStandardAlgorithms(dir);
        rsaKey = kms.createKey(RsaWrapper.ALG_ID).keyId();
        mlKemKey = kms.createKey(MlKemWrapper.ParameterSet.ML_KEM_768.algId()).keyId();
    }

    private static Envelope envelope(String alg, byte ciphertextByte) {
        return new Envelope(alg, "key-000001", "AES-256-GCM", new byte[] {1, 2}, new byte[] {ciphertextByte},
                WrappedDek.of("wrappedKey", new byte[] {7, 7}));
    }

    @Nested
    class When_sealing {

        @Test
        void the_envelope_names_the_wrap_algorithm_the_key_and_the_data_cipher() throws GeneralSecurityException, IOException {
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
            env.ciphertext()[0] ^= 1;

            assertThrows(AEADBadTagException.class, () -> env.open(kms));
        }
    }

    @Nested
    class When_the_algorithm_changes {

        @Test
        void old_and_new_envelopes_open_side_by_side() throws GeneralSecurityException, IOException {
            Envelope old = Envelope.seal("written last year".getBytes(UTF_8), kms, rsaKey, AesGcm.INSTANCE);
            Envelope current = Envelope.seal("written today".getBytes(UTF_8), kms, mlKemKey, ChaCha20Poly1305.INSTANCE);

            assertEquals("written last year", new String(old.open(kms), UTF_8));
            assertEquals("written today", new String(current.open(kms), UTF_8));
        }
    }

    @Nested
    class When_rewrapping {

        @Test
        void the_nonce_ciphertext_and_data_cipher_are_untouched() throws GeneralSecurityException, IOException {
            Envelope before = Envelope.seal(PLAINTEXT, kms, rsaKey, ChaCha20Poly1305.INSTANCE);

            Envelope after = before.rewrap(kms, mlKemKey);

            assertArrayEquals(before.nonce(), after.nonce());
            assertArrayEquals(before.ciphertext(), after.ciphertext());
            assertEquals(before.enc(), after.enc());
        }

        @Test
        void the_envelope_names_the_new_key_and_algorithm() throws GeneralSecurityException, IOException {
            Envelope after = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE).rewrap(kms, mlKemKey);

            assertEquals("ML-KEM-768", after.alg());
            assertEquals(mlKemKey, after.kid());
        }

        @Test
        void it_still_opens_after_the_old_key_is_disabled() throws GeneralSecurityException, IOException {
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
        void an_alg_that_does_not_match_the_key_is_caught() throws GeneralSecurityException, IOException {
            Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var forged = new Envelope("ML-KEM-768", env.kid(), env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

            var e = assertThrows(InvalidKeyException.class, () -> forged.open(kms));

            assertTrue(e.getMessage().contains("is RSA-OAEP-3072"));
        }

        @Test
        void an_envelope_with_no_key_id_cannot_be_opened() throws GeneralSecurityException, IOException {
            Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var anonymous = new Envelope(env.alg(), null, env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

            assertThrows(InvalidKeyException.class, () -> anonymous.open(kms));
        }

        @Test
        void an_unknown_data_cipher_is_named() throws GeneralSecurityException, IOException {
            Envelope env = Envelope.seal(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var odd = new Envelope(env.alg(), env.kid(), "ROT13", env.nonce(), env.ciphertext(), env.wrappedDek());

            var e = assertThrows(UnknownAlgorithmException.class, () -> odd.open(kms));

            assertTrue(e.getMessage().contains("ROT13"));
        }
    }

    @Nested
    class Comparing {

        @Test
        void equal_contents_make_equal_envelopes() {
            assertEquals(envelope("ML-KEM-768", (byte) 5), envelope("ML-KEM-768", (byte) 5));
            assertEquals(envelope("ML-KEM-768", (byte) 5).hashCode(), envelope("ML-KEM-768", (byte) 5).hashCode());
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
            assertNotEquals(WrappedDek.of("wrappedKey", new byte[] {1}), WrappedDek.of("wrappedKey", new byte[] {9}));
        }
    }

    @Nested
    class Printing {

        @Test
        void shows_names_and_sizes_but_never_the_bytes() {
            String text = new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", new byte[12], new byte[] {42, 42},
                    WrappedDek.of("wrappedKey", new byte[] {42})).toString();

            assertTrue(text.contains("alg=ML-KEM-768"));
            assertTrue(text.contains("ciphertext=2 bytes"));
            assertTrue(text.contains("wrappedKey=1 bytes"));
            assertFalse(text.contains("42"));
        }
    }
}
