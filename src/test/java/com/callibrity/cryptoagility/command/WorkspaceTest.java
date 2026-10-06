package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.kms.KeyMetadata;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class WorkspaceTest {

    @TempDir
    Path dataDir;

    @Nested
    class Choosing_the_key_for_new_data {

        @Test
        void creates_one_the_first_time_and_reuses_it_after() throws GeneralSecurityException, IOException {
            var ws = new Workspace(dataDir);

            KeyMetadata first = ws.currentKey("ML-KEM-768");
            KeyMetadata again = ws.currentKey("ML-KEM-768");

            assertEquals(first.keyId(), again.keyId());
            assertEquals(1, ws.kms().listKeys().size());
        }

        @Test
        void a_disabled_key_is_passed_over_for_a_new_one() throws GeneralSecurityException, IOException {
            var ws = new Workspace(dataDir);
            KeyMetadata old = ws.currentKey("ML-KEM-768");
            ws.kms().disableKey(old.keyId());

            KeyMetadata replacement = ws.currentKey("ML-KEM-768");

            assertNotEquals(old.keyId(), replacement.keyId());
        }
    }
}
