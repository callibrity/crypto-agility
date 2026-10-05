package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.WrappedDek;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Set;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ToyRsaWrapperTest {

    private static final byte[] PLAINTEXT = "customer record #1".getBytes(UTF_8);

    @Nested
    class As_a_key_wrapper {

        @RepeatedTest(20)
        void decrypts_what_it_encrypted() throws GeneralSecurityException {
            var toy = new ToyRsaWrapper();

            Envelope env = encrypt(PLAINTEXT, toy);

            assertEquals(ToyRsaWrapper.ALG_ID, env.alg());
            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(toy)));
        }

        @Test
        void round_trips_a_data_key_full_of_zero_bytes() throws GeneralSecurityException {
            var toy = new ToyRsaWrapper();
            var zeros = new SecretKeySpec(new byte[32], "AES");

            assertArrayEquals(new byte[32], toy.unwrap(toy.wrap(zeros)).getEncoded());
        }

        @Test
        void refuses_a_wrapped_key_of_the_wrong_size() {
            var toy = new ToyRsaWrapper();

            assertThrows(InvalidKeyException.class, () -> toy.unwrap(WrappedDek.of("wrappedKey", new byte[384])));
        }
    }

    @Nested
    class When_the_modulus_has_been_factored {

        // The textbook example: n = 61 * 53 = 3233, e = 17, d = 2753.
        private static final ToyRsaWrapper.PublicKey PUBLIC_KEY =
                new ToyRsaWrapper.PublicKey(BigInteger.valueOf(3233), BigInteger.valueOf(17));

        @Test
        void one_factor_is_enough_to_rebuild_the_private_exponent() {
            var rebuilt = ToyRsaWrapper.Keys.fromFactor(PUBLIC_KEY, BigInteger.valueOf(61));

            assertEquals(BigInteger.valueOf(2753), rebuilt.privateExponent());
        }

        @Test
        void the_rebuilt_key_opens_envelopes_without_the_original_private_key() throws GeneralSecurityException {
            var original = new ToyRsaWrapper(new ToyRsaWrapper.Keys(PUBLIC_KEY, BigInteger.valueOf(2753)));
            Envelope env = encrypt(PLAINTEXT, original);

            var rebuilt = new ToyRsaWrapper(ToyRsaWrapper.Keys.fromFactor(PUBLIC_KEY, BigInteger.valueOf(53)));

            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(rebuilt)));
        }
    }

    @Nested
    class Stored_as_fields {

        @Test
        void the_keys_survive_a_round_trip() {
            ToyRsaWrapper.Keys keys = ToyRsaWrapper.newKeys();

            assertEquals(keys, ToyRsaWrapper.Keys.fromFields(keys.toFields()));
        }

        @Test
        void the_public_key_fields_leave_out_the_private_exponent() {
            ToyRsaWrapper.Keys keys = ToyRsaWrapper.newKeys();

            assertEquals(Set.of("modulus", "exponent"), keys.publicKey().toFields().keySet());
        }
    }
}
