package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.cipher.DataKeySpec;
import com.callibrity.cryptoagility.wrapper.AesKwWrapper;
import com.callibrity.cryptoagility.wrapper.KeyWrapper;
import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class LocalKmsTest {

    @TempDir
    Path dir;

    private LocalKms kms;

    @BeforeEach
    void open_the_kms() {
        kms = LocalKms.withStandardAlgorithms(dir);
    }

    static List<String> algorithms() {
        return LocalKms.withStandardAlgorithms(Path.of("unused")).algorithms();
    }

    @Nested
    class For_every_algorithm_it_offers {

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.kms.LocalKmsTest#algorithms")
        void a_data_key_it_wraps_comes_back_unchanged(String algorithm) throws GeneralSecurityException, IOException {
            String keyId = kms.createKey(algorithm).keyId();

            DataKey dataKey = kms.generateDataKey(keyId, DataKeySpec.AES_256);

            assertEquals(algorithm, dataKey.algorithm());
            assertArrayEquals(dataKey.key().getEncoded(), kms.decryptDataKey(keyId, dataKey.wrapped()).getEncoded());
        }

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.kms.LocalKmsTest#algorithms")
        void its_keys_still_work_after_a_restart(String algorithm) throws GeneralSecurityException, IOException {
            String keyId = kms.createKey(algorithm).keyId();
            DataKey dataKey = kms.generateDataKey(keyId, DataKeySpec.AES_256);

            var restarted = LocalKms.withStandardAlgorithms(dir);

            assertArrayEquals(dataKey.key().getEncoded(),
                    restarted.decryptDataKey(keyId, dataKey.wrapped()).getEncoded());
        }

        @ParameterizedTest
        @MethodSource("com.callibrity.cryptoagility.kms.LocalKmsTest#algorithms")
        void it_can_describe_it_for_an_inventory(String algorithm) throws GeneralSecurityException {
            AlgorithmInfo info = kms.describeAlgorithm(algorithm);

            assertNotNull(info.facts());
            assertNotNull(info.provider());
        }
    }

    @Nested
    class When_generating_data_keys {

        @Test
        void makes_the_size_and_kind_asked_for() throws GeneralSecurityException, IOException {
            String keyId = kms.createKey("ML-KEM-768").keyId();

            SecretKey chacha = kms.generateDataKey(keyId, DataKeySpec.CHACHA20).key();

            assertEquals("ChaCha20", chacha.getAlgorithm());
            assertEquals(32, chacha.getEncoded().length);
        }

        @Test
        void makes_a_different_key_every_time() throws GeneralSecurityException, IOException {
            String keyId = kms.createKey("ML-KEM-768").keyId();

            byte[] first = kms.generateDataKey(keyId, DataKeySpec.AES_256).key().getEncoded();
            byte[] second = kms.generateDataKey(keyId, DataKeySpec.AES_256).key().getEncoded();

            assertFalse(Arrays.equals(first, second));
        }
    }

    @Nested
    class When_re_encrypting {

        @Test
        void the_data_key_moves_to_the_new_key_unchanged() throws GeneralSecurityException, IOException {
            String rsa = kms.createKey("RSA-OAEP-3072").keyId();
            String mlKem = kms.createKey("ML-KEM-1024").keyId();
            DataKey dataKey = kms.generateDataKey(rsa, DataKeySpec.AES_256);

            WrappedDek moved = kms.reEncrypt(rsa, dataKey.wrapped(), mlKem);

            assertArrayEquals(dataKey.key().getEncoded(), kms.decryptDataKey(mlKem, moved).getEncoded());
        }
    }

    @Nested
    class On_start_up {

        @Test
        void bouncycastle_is_ready_before_any_key_is_loaded() {
            new LocalKms(dir);

            assertNotNull(Security.getProvider("BC"));
            assertNotNull(Security.getProvider("BCPQC"));
        }

        @Test
        void the_jdk_still_serves_what_it_can() throws GeneralSecurityException {
            assertEquals("SunJCE", kms.describeAlgorithm("ML-KEM-768").provider());
        }
    }

    @Nested
    class Managing_keys {

        @Test
        void lists_keys_oldest_first_with_what_they_are() throws GeneralSecurityException, IOException {
            String first = kms.createKey("RSA-OAEP-3072").keyId();
            String second = kms.createKey("HQC-192").keyId();

            List<KeyMetadata> keys = kms.listKeys();

            assertEquals(List.of(first, second), keys.stream().map(KeyMetadata::keyId).toList());
            assertEquals("HQC-192", keys.get(1).algorithm());
            assertTrue(keys.get(1).enabled());
        }

        @Test
        void a_disabled_key_refuses_to_work_until_it_is_enabled_again() throws GeneralSecurityException, IOException {
            String keyId = kms.createKey("AES-256-KW").keyId();
            DataKey dataKey = kms.generateDataKey(keyId, DataKeySpec.AES_256);

            kms.disableKey(keyId);

            assertFalse(kms.describeKey(keyId).enabled());
            assertThrows(KeyDisabledException.class, () -> kms.decryptDataKey(keyId, dataKey.wrapped()));
            assertThrows(KeyDisabledException.class, () -> kms.generateDataKey(keyId, DataKeySpec.AES_256));

            kms.enableKey(keyId);

            assertArrayEquals(dataKey.key().getEncoded(), kms.decryptDataKey(keyId, dataKey.wrapped()).getEncoded());
        }

        @Test
        void an_unknown_key_is_refused() {
            assertThrows(UnknownKeyException.class, () -> kms.describeKey("key-nothere"));
        }

        @Test
        void an_unknown_algorithm_is_refused() {
            assertThrows(UnknownAlgorithmException.class, () -> kms.createKey("SIKE-p434"));
        }

        @Test
        void a_damaged_key_file_breaks_only_that_key() throws GeneralSecurityException, IOException {
            String damaged = kms.createKey("ML-KEM-768").keyId();
            String healthy = kms.createKey("ML-KEM-768").keyId();
            Path file = dir.resolve(damaged + ".key");
            Files.writeString(file, Files.readString(file).replaceFirst("private=", "private=!!"));
            var restarted = LocalKms.withStandardAlgorithms(dir);

            assertThrows(GeneralSecurityException.class, () -> restarted.generateDataKey(damaged, DataKeySpec.AES_256));
            assertNotNull(restarted.generateDataKey(healthy, DataKeySpec.AES_256));
        }
    }

    @Nested
    class When_key_material_is_incomplete {

        @Test
        void a_missing_field_is_named() throws GeneralSecurityException, IOException {
            String keyId = kms.createKey("ML-KEM-512").keyId();
            Path file = dir.resolve(keyId + ".key");
            Files.writeString(file, Files.readString(file).replaceFirst("private=[^\\n]*\\n", ""));
            var restarted = LocalKms.withStandardAlgorithms(dir);

            var e = assertThrows(GeneralSecurityException.class, () -> restarted.generateDataKey(keyId, DataKeySpec.AES_256));

            assertTrue(e.getMessage().contains("no private field"));
        }
    }

    @Nested
    class For_an_algorithm_that_cannot_describe_itself {

        @Test
        void offers_no_facts_rather_than_failing() throws GeneralSecurityException {
            kms.register(KeyTypes.secretKey("PLAIN", AesKwWrapper::newKey, key -> new PlainWrapper(new AesKwWrapper(key))));

            AlgorithmInfo info = kms.describeAlgorithm("PLAIN");

            assertNull(info.facts());
            assertNull(info.provider());
        }
    }

    // Does the work of the wrapper it is given, but says nothing about itself.
    private record PlainWrapper(KeyWrapper inner) implements KeyWrapper {

        @Override
        public String algId() { return "PLAIN"; }

        @Override
        public WrappedDek wrap(SecretKey dek) throws GeneralSecurityException { return inner.wrap(dek); }

        @Override
        public SecretKey unwrap(WrappedDek w) throws GeneralSecurityException { return inner.unwrap(w); }
    }

}
