package com.callibrity.cryptoagility.wrapper;

import com.callibrity.cryptoagility.envelope.Inventoried;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DefaultWrappersTest {

    private static final SecretKey DATA_KEY = new SecretKeySpec(new byte[32], "AES");

    // Each wrapper made with its no-argument constructor, which generates a fresh key.
    static List<KeyWrapper> wrappers() throws GeneralSecurityException {
        return List.of(new RsaWrapper(), new EcdhWrapper(), new AesKwWrapper(), new MlKemWrapper(),
                new HybridWrapper(), new HqcWrapper());
    }

    @Nested
    class Made_with_a_fresh_key {

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.wrapper.DefaultWrappersTest#wrappers")
        void unwraps_what_it_wrapped(KeyWrapper wrapper) throws GeneralSecurityException {
            assertArrayEquals(DATA_KEY.getEncoded(), wrapper.unwrap(wrapper.wrap(DATA_KEY)).getEncoded());
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
            assertEquals("AES-256-KW", new AesKwWrapper().algId());
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
}
