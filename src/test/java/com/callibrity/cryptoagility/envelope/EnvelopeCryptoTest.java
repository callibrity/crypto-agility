package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.wrappers.AesKwWrapper;
import com.callibrity.cryptoagility.wrappers.EcdhWrapper;
import com.callibrity.cryptoagility.wrappers.HqcWrapper;
import com.callibrity.cryptoagility.wrappers.HybridWrapper;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.List;

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

    private static KeyWrapper rsa;
    private static KeyWrapper mlKem;
    private static KeyWrapper hybrid;
    private static KeyWrapper hqc;
    private static KeyWrapper ecdh;
    private static KeyWrapper aesKw;
    private static WrapperRegistry registry;

    @BeforeAll
    static void create_wrappers() throws GeneralSecurityException {
        rsa = new RsaWrapper();
        mlKem = new MlKemWrapper();
        hybrid = new HybridWrapper();
        hqc = new HqcWrapper();
        ecdh = new EcdhWrapper();
        aesKw = new AesKwWrapper();
        registry = new WrapperRegistry()
                .register(rsa).register(mlKem).register(hybrid).register(hqc).register(ecdh).register(aesKw);
    }

    static List<KeyWrapper> wrappers() {
        return List.of(rsa, mlKem, hybrid, hqc, ecdh, aesKw);
    }

    @Nested
    class With_any_wrapper {

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.envelope.EnvelopeCryptoTest#wrappers")
        void decrypts_what_it_encrypted(KeyWrapper wrapper) throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, wrapper);

            assertArrayEquals(PLAINTEXT, decrypt(env, registry));
        }

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.envelope.EnvelopeCryptoTest#wrappers")
        void records_the_wrapping_algorithm_in_the_envelope(KeyWrapper wrapper) throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, wrapper);

            assertEquals(wrapper.algId(), env.alg());
        }

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.envelope.EnvelopeCryptoTest#wrappers")
        void rejects_tampered_ciphertext(KeyWrapper wrapper) throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, wrapper);
            env.ciphertext()[0] ^= 1;

            assertThrows(AEADBadTagException.class, () -> decrypt(env, registry));
        }
    }

    @Nested
    class When_the_algorithm_is_swapped {

        @Test
        void reads_old_and_new_envelopes_side_by_side() throws GeneralSecurityException {
            Envelope old = encrypt("written last year".getBytes(UTF_8), rsa);
            Envelope current = encrypt("written today".getBytes(UTF_8), mlKem);

            assertEquals("written last year", new String(decrypt(old, registry), UTF_8));
            assertEquals("written today", new String(decrypt(current, registry), UTF_8));
        }

        @Test
        void each_algorithm_stores_its_own_fields_for_the_wrapped_key() throws GeneralSecurityException {
            assertEquals(List.of("wrappedKey"), fieldsOf(encrypt(PLAINTEXT, rsa)));
            assertEquals(List.of("wrappedKey", "kemCt", "wrapNonce"), fieldsOf(encrypt(PLAINTEXT, mlKem)));
            assertEquals(List.of("wrappedKey", "ephemeralKey", "kemCt", "wrapNonce"), fieldsOf(encrypt(PLAINTEXT, hybrid)));
            assertEquals(List.of("wrappedKey", "kemCt", "wrapNonce"), fieldsOf(encrypt(PLAINTEXT, hqc)));
            assertEquals(List.of("wrappedKey", "ephemeralKey", "wrapNonce"), fieldsOf(encrypt(PLAINTEXT, ecdh)));
            assertEquals(List.of("wrappedKey"), fieldsOf(encrypt(PLAINTEXT, aesKw)));
        }

        private List<String> fieldsOf(Envelope env) {
            return List.copyOf(env.wrappedDek().fields().keySet());
        }
    }

    @Nested
    class When_the_algorithm_is_not_registered {

        @Test
        void fails_naming_the_missing_algorithm() throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, rsa);
            var rsaRetired = new WrapperRegistry().register(mlKem);

            var e = assertThrows(UnknownAlgorithmException.class, () -> decrypt(env, rsaRetired));

            assertTrue(e.getMessage().contains("RSA-OAEP-3072"));
        }
    }

    @Nested
    class When_the_wrong_wrapper_is_assumed {

        @Test
        void a_kem_wrapper_refuses_a_key_that_rsa_wrapped() throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, rsa);

            assertThrows(GeneralSecurityException.class, () -> mlKem.unwrap(env.wrappedDek()));
            assertThrows(GeneralSecurityException.class, () -> hybrid.unwrap(env.wrappedDek()));
        }

        @Test
        void rsa_refuses_a_key_that_a_kem_wrapped() throws GeneralSecurityException {
            Envelope env = encrypt(PLAINTEXT, mlKem);

            assertThrows(GeneralSecurityException.class, () -> rsa.unwrap(env.wrappedDek()));
        }
    }

    @Nested
    class When_rewrapping {

        @Test
        void leaves_the_nonce_and_ciphertext_untouched() throws GeneralSecurityException {
            Envelope before = encrypt(PLAINTEXT, rsa);

            Envelope after = rewrap(before, registry, mlKem);

            assertArrayEquals(before.nonce(), after.nonce());
            assertArrayEquals(before.ciphertext(), after.ciphertext());
        }

        @Test
        void names_the_new_algorithm() throws GeneralSecurityException {
            Envelope after = rewrap(encrypt(PLAINTEXT, rsa), registry, mlKem);

            assertEquals("ML-KEM-768", after.alg());
        }

        @Test
        void stays_readable_after_the_old_algorithm_is_retired() throws GeneralSecurityException {
            Envelope after = rewrap(encrypt(PLAINTEXT, rsa), registry, mlKem);
            var rsaRetired = new WrapperRegistry().register(mlKem);

            assertArrayEquals(PLAINTEXT, decrypt(after, rsaRetired));
        }
    }
}
