package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.cipher.AesGcm;
import com.callibrity.cryptoagility.cipher.ChaCha20Poly1305;
import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.kms.KeyDisabledException;
import com.callibrity.cryptoagility.kms.LocalKms;
import com.callibrity.cryptoagility.wrapper.MlKemWrapper;
import com.callibrity.cryptoagility.wrapper.RsaWrapper;
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

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.rewrap;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeCryptoTest {

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

    @Nested
    class When_encrypting {

        @Test
        void the_envelope_names_the_wrap_algorithm_the_key_and_the_data_cipher() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, mlKemKey, AesGcm.INSTANCE);

            assertEquals("ML-KEM-768", env.alg());
            assertEquals(mlKemKey, env.kid());
            assertEquals("AES-256-GCM", env.enc());
        }

        @Test
        void either_data_cipher_round_trips() throws GeneralSecurityException, IOException {
            for (DataCipher cipher : DataCiphers.all()) {
                Envelope env = encrypt(PLAINTEXT, kms, rsaKey, cipher);

                assertEquals(cipher.algId(), env.enc());
                assertArrayEquals(PLAINTEXT, decrypt(env, kms));
            }
        }

        @Test
        void tampered_ciphertext_is_rejected() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            env.ciphertext()[0] ^= 1;

            assertThrows(AEADBadTagException.class, () -> decrypt(env, kms));
        }
    }

    @Nested
    class When_the_algorithm_changes {

        @Test
        void old_and_new_envelopes_read_side_by_side() throws GeneralSecurityException, IOException {
            Envelope old = encrypt("written last year".getBytes(UTF_8), kms, rsaKey, AesGcm.INSTANCE);
            Envelope current = encrypt("written today".getBytes(UTF_8), kms, mlKemKey, ChaCha20Poly1305.INSTANCE);

            assertEquals("written last year", new String(decrypt(old, kms), UTF_8));
            assertEquals("written today", new String(decrypt(current, kms), UTF_8));
        }
    }

    @Nested
    class When_rewrapping {

        @Test
        void the_nonce_ciphertext_and_data_cipher_are_untouched() throws GeneralSecurityException, IOException {
            Envelope before = encrypt(PLAINTEXT, kms, rsaKey, ChaCha20Poly1305.INSTANCE);

            Envelope after = rewrap(before, kms, mlKemKey);

            assertArrayEquals(before.nonce(), after.nonce());
            assertArrayEquals(before.ciphertext(), after.ciphertext());
            assertEquals(before.enc(), after.enc());
        }

        @Test
        void the_envelope_names_the_new_key_and_algorithm() throws GeneralSecurityException, IOException {
            Envelope after = rewrap(encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE), kms, mlKemKey);

            assertEquals("ML-KEM-768", after.alg());
            assertEquals(mlKemKey, after.kid());
        }

        @Test
        void it_still_reads_after_the_old_key_is_disabled() throws GeneralSecurityException, IOException {
            Envelope after = rewrap(encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE), kms, mlKemKey);

            kms.disableKey(rsaKey);

            assertArrayEquals(PLAINTEXT, decrypt(after, kms));
        }
    }

    @Nested
    class When_something_is_wrong {

        @Test
        void a_disabled_key_cannot_open_its_envelopes() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);

            kms.disableKey(rsaKey);

            assertThrows(KeyDisabledException.class, () -> decrypt(env, kms));
        }

        @Test
        void an_alg_that_does_not_match_the_key_is_caught() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var forged = new Envelope("ML-KEM-768", env.kid(), env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

            var e = assertThrows(InvalidKeyException.class, () -> decrypt(forged, kms));

            assertTrue(e.getMessage().contains("is RSA-OAEP-3072"));
        }

        @Test
        void an_envelope_with_no_key_id_cannot_be_opened() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var anonymous = new Envelope(env.alg(), null, env.enc(), env.nonce(), env.ciphertext(), env.wrappedDek());

            assertThrows(InvalidKeyException.class, () -> decrypt(anonymous, kms));
        }

        @Test
        void an_unknown_data_cipher_is_named() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, kms, rsaKey, AesGcm.INSTANCE);
            var odd = new Envelope(env.alg(), env.kid(), "ROT13", env.nonce(), env.ciphertext(), env.wrappedDek());

            var e = assertThrows(UnknownAlgorithmException.class, () -> decrypt(odd, kms));

            assertTrue(e.getMessage().contains("ROT13"));
        }
    }
}
