package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ShellTest {

    @TempDir
    Path dataDir;

    private Workspace ws;
    private Shell shell;

    @BeforeEach
    void open_a_fresh_session() {
        ws = new Workspace(dataDir);
        shell = new Shell(ws);
    }

    private List<String> storedAlgorithms() throws IOException {
        return ws.envelopes().all().stream().map(stored -> stored.envelope().alg()).toList();
    }

    private String plaintextOf(int index) throws IOException, GeneralSecurityException {
        Envelope env = ws.envelopes().all().get(index).envelope();
        return new String(decrypt(env, ws.registry()), UTF_8);
    }

    @Nested
    class When_a_session_starts {

        @Test
        void new_data_is_wrapped_with_rsa() {
            assertEquals("RSA-OAEP-3072", shell.current());
        }

        @Test
        void generates_no_keys_until_one_is_needed() throws IOException {
            shell.execute("list");

            assertTrue(ws.keys().all().isEmpty());
        }
    }

    @Nested
    class When_the_algorithm_is_changed_with_use {

        @Test
        void later_writes_follow_it_and_earlier_records_keep_theirs() throws IOException {
            shell.execute("write customer record #1");
            shell.execute("use ML-KEM-768");
            shell.execute("write customer record #2");

            assertEquals(List.of("RSA-OAEP-3072", "ML-KEM-768"), storedAlgorithms());
        }

        @Test
        void an_unknown_algorithm_is_refused_and_the_current_one_kept() {
            shell.execute("use SIKE-p434");

            assertEquals("RSA-OAEP-3072", shell.current());
        }

        @Test
        void use_on_its_own_changes_nothing() {
            shell.execute("use ML-KEM-768");
            shell.execute("use");

            assertEquals("ML-KEM-768", shell.current());
        }

        @Test
        void rewrap_moves_everything_to_it() throws IOException {
            shell.execute("write customer record #1");
            shell.execute("write customer record #2");
            shell.execute("use ML-KEM-768");

            shell.execute("rewrap");

            assertEquals(List.of("ML-KEM-768", "ML-KEM-768"), storedAlgorithms());
        }
    }

    @Nested
    class When_writing {

        @Test
        void stores_the_text_exactly_as_typed() throws IOException, GeneralSecurityException {
            shell.execute("write   it's 100% fine, \"really\"!  ");

            assertEquals("it's 100% fine, \"really\"!", plaintextOf(0));
        }

        @Test
        void drops_quotes_that_surround_the_whole_text() throws IOException, GeneralSecurityException {
            shell.execute("write \"customer record #1\"");

            assertEquals("customer record #1", plaintextOf(0));
        }

        @Test
        void stores_nothing_when_no_text_is_given() throws IOException {
            shell.execute("write");

            assertTrue(ws.envelopes().all().isEmpty());
        }
    }

    @Nested
    class When_completing_what_is_typed {

        @Test
        void offers_every_registered_algorithm() {
            assertEquals(List.of("RSA-OAEP-3072", "ECDH-X25519", "AES-256-KW", "ML-KEM-768", "X25519+ML-KEM-768", "HQC-192",
                    "RSA-TOY-96"), shell.algorithms());
        }

        @Test
        void offers_the_ids_of_stored_records() {
            shell.execute("write customer record #1");

            assertEquals(List.of("record-0001"), shell.recordIds());
        }
    }

    @Nested
    class When_listing_keys {

        @Test
        void describes_key_pairs_and_secret_keys_alike() {
            shell.execute("use AES-256-KW");

            assertTrue(shell.execute("keys"));
        }
    }

    @Nested
    class When_a_line_is_not_a_command {

        @Test
        void an_unknown_command_keeps_the_session_going() {
            assertTrue(shell.execute("frobnicate"));
        }

        @Test
        void a_blank_line_keeps_the_session_going() {
            assertTrue(shell.execute("   "));
        }

        @Test
        void a_command_that_fails_keeps_the_session_going() {
            assertTrue(shell.execute("show record-0099"));
        }
    }

    @Nested
    class When_asked_to_leave {

        @Test
        void exit_ends_the_session() {
            assertFalse(shell.execute("exit"));
        }

        @Test
        void quit_ends_the_session() {
            assertFalse(shell.execute("quit"));
        }
    }

    @Nested
    class When_a_copied_envelope_is_named_by_path {

        @Test
        void it_is_selected_from_wherever_it_is() throws IOException {
            shell.execute("write customer record #1");
            Path original = dataDir.resolve("envelopes").resolve("record-0001.envelope");
            Path copy = Files.copy(original, dataDir.resolve("harvested.envelope"));

            List<Stored> selected = StoreCommands.select(ws, copy.toString());

            assertEquals("RSA-OAEP-3072", selected.getFirst().envelope().alg());
        }
    }
}
