package com.callibrity.cryptoagility.store;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeStoreTest {

    private static final Envelope DIRECT =
            new Envelope("RSA-OAEP-3072", "key-000001", "AES-256-GCM", bytes(12, 1), bytes(40, 2), WrappedDek.of("wrappedKey", bytes(384, 3)));
    private static final Envelope KEM =
            new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", bytes(12, 4), bytes(40, 5), new WrappedDek(kemFields()));

    @TempDir
    Path dir;

    private static Map<String, byte[]> kemFields() {
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put("wrappedKey", bytes(48, 6));
        fields.put("kemCt", bytes(1088, 7));
        fields.put("wrapNonce", bytes(12, 8));
        return fields;
    }

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
        void keeps_every_field_of_the_wrapped_key_in_order() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(KEM);

            Envelope loaded = store.all().getFirst().envelope();
            assertArrayEquals(KEM.nonce(), loaded.nonce());
            assertArrayEquals(KEM.ciphertext(), loaded.ciphertext());
            Map<String, byte[]> fields = loaded.wrappedDek().fields();
            assertEquals(List.of("wrappedKey", "kemCt", "wrapNonce"), List.copyOf(fields.keySet()));
            assertArrayEquals(bytes(48, 6), fields.get("wrappedKey"));
            assertArrayEquals(bytes(1088, 7), fields.get("kemCt"));
            assertArrayEquals(bytes(12, 8), fields.get("wrapNonce"));
        }

        @Test
        void stores_a_field_it_has_never_heard_of() throws IOException {
            var store = new EnvelopeStore(dir);
            var novel = new Envelope("SOMETHING-NEW", "key-000001", "AES-256-GCM", bytes(12, 1), bytes(40, 2), WrappedDek.of("keyVersion", bytes(4, 9)));

            store.add(novel);

            assertArrayEquals(bytes(4, 9), store.all().getFirst().envelope().wrappedDek().fields().get("keyVersion"));
        }

        @Test
        void refuses_a_wrap_field_that_would_shadow_the_envelope_header() {
            var store = new EnvelopeStore(dir);
            var clashing = new Envelope("SOMETHING-NEW", "key-000001", "AES-256-GCM", bytes(12, 1), bytes(40, 2), WrappedDek.of("alg", bytes(4, 9)));

            assertThrows(IllegalArgumentException.class, () -> store.add(clashing));
        }

        @Test
        void stores_only_the_fields_the_wrapper_produced() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(DIRECT);

            assertEquals(Set.of("wrappedKey"), store.all().getFirst().envelope().wrappedDek().fields().keySet());
        }

        @Test
        void keeps_the_key_id_and_data_cipher() throws IOException {
            var store = new EnvelopeStore(dir);

            store.add(KEM);

            Envelope loaded = store.all().getFirst().envelope();
            assertEquals("key-000001", loaded.kid());
            assertEquals("AES-256-GCM", loaded.enc());
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

    @Nested
    class Reading_a_hand_edited_file {

        @Test
        void skips_comments_blank_lines_and_lines_without_a_value() throws IOException {
            var store = new EnvelopeStore(dir);
            String id = store.add(KEM);
            Path file = dir.resolve(id + ".envelope");
            Files.writeString(file, "# a note\n\nnot a field\n" + Files.readString(file));

            assertEquals("ML-KEM-768", store.all().getFirst().envelope().alg());
        }

        @Test
        void reports_a_missing_field_as_damage() throws IOException {
            var store = new EnvelopeStore(dir);
            String id = store.add(KEM);
            Path file = dir.resolve(id + ".envelope");
            Files.writeString(file, Files.readString(file).replaceFirst("nonce=[^\\n]*\\n", ""));

            Stored stored = store.all().getFirst();

            assertTrue(stored.damaged());
            assertTrue(stored.problem().contains("has no 'nonce' field"));
        }

        @Test
        void an_envelope_without_header_names_is_stored_without_them() throws IOException {
            var store = new EnvelopeStore(dir);
            var bare = new Envelope(null, null, null, bytes(12, 1), bytes(40, 2), WrappedDek.of("wrappedKey", bytes(4, 3)));

            String id = store.add(bare);

            String text = Files.readString(dir.resolve(id + ".envelope"));
            assertFalse(text.contains("alg="));
            assertFalse(text.contains("null"));
        }
    }

}
