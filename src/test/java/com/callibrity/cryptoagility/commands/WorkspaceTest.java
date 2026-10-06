package com.callibrity.cryptoagility.commands;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class WorkspaceTest {

    @TempDir
    Path dataDir;

    @Nested
    class When_a_key_cannot_be_loaded {

        @Test
        void fails_every_time_rather_than_handing_out_a_partial_registry() throws Exception {
            Files.createDirectories(dataDir.resolve("keys"));
            Files.writeString(dataDir.resolve("keys").resolve("ml-kem-768.keypair"),
                    "algorithm=ML-KEM\npublic=AAAA\nprivate=AAAA\n");
            var ws = new Workspace(dataDir);

            assertThrows(Exception.class, ws::registry);
            assertThrows(Exception.class, ws::registry);
        }
    }
}
