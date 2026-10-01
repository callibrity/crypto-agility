package com.callibrity.cryptoagility.store;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeStoreTest {

    private static final Envelope DIRECT =
            new Envelope("RSA-OAEP-3072", bytes(12, 1), bytes(40, 2), bytes(384, 3), null, null);
    private static final Envelope KEM =
            new Envelope("ML-KEM-768", bytes(12, 4), bytes(40, 5), bytes(48, 6), bytes(1088, 7), bytes(12, 8));

    @TempDir
    Path dir;

    private static byte[] bytes(int length, int fill) {
        byte[] b = new byte[length];
        Arrays.fill(b, (byte) fill);
        return b;
    }

    @Nested
    class When_empty {

        @Test
        void lists_nothing_even_before_the_directory_exists() throws IOException {
            var store = new EnvelopeStore(dir.resolve("not-created-yet"));

            assertTrue(store.all().isEmpty());
        }
    }

    @Nested
    class When_envelopes_are_added {

        @Test
        void returns_them_in_the_order_they_were_written() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(DIRECT);
            store.add(KEM);

            List<Stored> all = store.all();
            assertEquals(List.of("record-0001", "record-0002"), all.stream().map(Stored::id).toList());
            assertEquals(List.of("RSA-OAEP-3072", "ML-KEM-768"), all.stream().map(s -> s.envelope().alg()).toList());
        }

        @Test
        void keeps_every_field_of_a_kem_envelope() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(KEM);

            Envelope loaded = store.all().getFirst().envelope();
            assertArrayEquals(KEM.nonce(), loaded.nonce());
            assertArrayEquals(KEM.ciphertext(), loaded.ciphertext());
            assertArrayEquals(KEM.wrappedKey(), loaded.wrappedKey());
            assertArrayEquals(KEM.kemCt(), loaded.kemCt());
            assertArrayEquals(KEM.wrapNonce(), loaded.wrapNonce());
        }

        @Test
        void leaves_the_kem_fields_absent_for_a_directly_wrapped_key() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(DIRECT);

            Envelope loaded = store.all().getFirst().envelope();
            assertNull(loaded.kemCt());
            assertNull(loaded.wrapNonce());
        }

        @Test
        void writes_the_algorithm_as_readable_text() throws IOException {
            var store = new EnvelopeStore(dir);

            String id = store.add(KEM);

            assertTrue(Files.readAllLines(dir.resolve(id + ".envelope")).contains("alg=ML-KEM-768"));
        }

        @Test
        void does_not_reuse_the_id_of_a_record_that_still_exists() throws IOException {
            var store = new EnvelopeStore(dir);
            store.add(DIRECT);
            store.add(DIRECT);
            Files.delete(dir.resolve("record-0001.envelope"));

            String id = store.add(KEM);

            assertEquals("record-0003", id);
        }
    }

    @Nested
    class When_an_envelope_is_replaced {

        @Test
        void keeps_the_id_and_stores_the_new_contents() throws IOException {
            var store = new EnvelopeStore(dir);
            String id = store.add(DIRECT);

            store.put(id, KEM);

            List<Stored> all = store.all();
            assertEquals(1, all.size());
            assertEquals("ML-KEM-768", all.getFirst().envelope().alg());
        }
    }
}
