package com.callibrity.cryptoagility.wrappers;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ParameterSetTest {

    private static final byte[] PLAINTEXT = "customer record #1".getBytes(UTF_8);

    private static String oidIn(PublicKey key) {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getAlgorithm().getId();
    }

    @Nested
    class For_each_ml_kem_parameter_set {

        @ParameterizedTest
        @EnumSource(MlKemWrapper.ParameterSet.class)
        void decrypts_what_it_encrypted_and_names_itself(MlKemWrapper.ParameterSet set) throws GeneralSecurityException {
            var wrapper = new MlKemWrapper(set, MlKemWrapper.newKeyPair(set));

            Envelope env = encrypt(PLAINTEXT, wrapper);

            assertEquals(set.algId(), env.alg());
            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(wrapper)));
        }

        @ParameterizedTest
        @EnumSource(MlKemWrapper.ParameterSet.class)
        void reports_the_oid_the_jdk_writes_into_its_keys(MlKemWrapper.ParameterSet set) throws GeneralSecurityException {
            var kp = MlKemWrapper.newKeyPair(set);

            assertEquals(oidIn(kp.getPublic()), new MlKemWrapper(set, kp).facts().oid());
        }

        @Test
        void the_levels_follow_fips_203() throws GeneralSecurityException {
            assertEquals(1, level(MlKemWrapper.ParameterSet.ML_KEM_512));
            assertEquals(3, level(MlKemWrapper.ParameterSet.ML_KEM_768));
            assertEquals(5, level(MlKemWrapper.ParameterSet.ML_KEM_1024));
        }

        @Test
        void refuses_a_key_from_a_different_parameter_set() throws GeneralSecurityException {
            var key768 = MlKemWrapper.newKeyPair(MlKemWrapper.ParameterSet.ML_KEM_768);

            assertThrows(InvalidKeyException.class, () -> new MlKemWrapper(MlKemWrapper.ParameterSet.ML_KEM_1024, key768));
        }

        @Test
        void defaults_to_768() throws GeneralSecurityException {
            assertEquals("ML-KEM-768", new MlKemWrapper().algId());
        }

        private int level(MlKemWrapper.ParameterSet set) throws GeneralSecurityException {
            return new MlKemWrapper(set, MlKemWrapper.newKeyPair(set)).facts().nistQuantumSecurityLevel();
        }
    }

    @Nested
    class For_each_hqc_parameter_set {

        @ParameterizedTest
        @EnumSource(HqcWrapper.ParameterSet.class)
        void decrypts_what_it_encrypted_and_names_itself(HqcWrapper.ParameterSet set) throws GeneralSecurityException {
            var wrapper = new HqcWrapper(set, HqcWrapper.newKeyPair(set));

            Envelope env = encrypt(PLAINTEXT, wrapper);

            assertEquals(set.algId(), env.alg());
            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(wrapper)));
        }

        @ParameterizedTest
        @EnumSource(HqcWrapper.ParameterSet.class)
        void reports_the_oid_bouncycastle_writes_into_its_keys(HqcWrapper.ParameterSet set)
                throws GeneralSecurityException {
            var kp = HqcWrapper.newKeyPair(set);

            assertEquals(oidIn(kp.getPublic()), new HqcWrapper(set, kp).facts().provisionalOid());
        }

        @Test
        void refuses_a_key_from_a_different_parameter_set() throws GeneralSecurityException {
            var key192 = HqcWrapper.newKeyPair(HqcWrapper.ParameterSet.HQC_192);

            assertThrows(InvalidKeyException.class, () -> new HqcWrapper(HqcWrapper.ParameterSet.HQC_256, key192));
        }

        @Test
        void defaults_to_192() throws GeneralSecurityException {
            assertEquals("HQC-192", new HqcWrapper().algId());
        }
    }
}
