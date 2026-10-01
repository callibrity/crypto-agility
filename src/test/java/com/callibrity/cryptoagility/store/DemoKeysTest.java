package com.callibrity.cryptoagility.store;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.wrappers.HybridWrapper;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DemoKeysTest {

    private static final byte[] PLAINTEXT = "written by an earlier run".getBytes(UTF_8);

    @TempDir
    Path dir;

    @Nested
    class When_keys_are_loaded_again_by_a_later_run {

        @Test
        void rsa_still_opens_what_it_wrapped() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, rsa());

            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(rsa())));
        }

        @Test
        void ml_kem_still_opens_what_it_wrapped() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, mlKem());

            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(mlKem())));
        }

        @Test
        void the_hybrid_still_opens_what_it_wrapped() throws GeneralSecurityException, IOException {
            Envelope env = encrypt(PLAINTEXT, hybrid());

            assertArrayEquals(PLAINTEXT, decrypt(env, new WrapperRegistry().register(hybrid())));
        }
    }

    // Each call builds a fresh DemoKeys over the same directory, as a new process would.

    private KeyWrapper rsa() throws GeneralSecurityException, IOException {
        return new RsaWrapper(new DemoKeys(dir).keyPair("rsa", RsaWrapper::newKeyPair));
    }

    private KeyWrapper mlKem() throws GeneralSecurityException, IOException {
        return new MlKemWrapper(new DemoKeys(dir).keyPair("ml-kem", MlKemWrapper::newKeyPair));
    }

    private KeyWrapper hybrid() throws GeneralSecurityException, IOException {
        var keys = new DemoKeys(dir);
        return new HybridWrapper(
                keys.keyPair("x25519", HybridWrapper::newX25519KeyPair),
                keys.keyPair("hybrid-ml-kem", MlKemWrapper::newKeyPair));
    }
}
