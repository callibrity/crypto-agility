package com.callibrity.cryptoagility.envelope;

import com.callibrity.cryptoagility.wrapper.WrappedDek;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeTest {

    private static Envelope envelope(String alg, byte ciphertextByte) {
        return new Envelope(alg, "key-000001", "AES-256-GCM", new byte[] {1, 2}, new byte[] {ciphertextByte},
                WrappedDek.of("wrappedKey", new byte[] {7, 7}));
    }

    @Nested
    class Comparing {

        @Test
        void equal_contents_make_equal_envelopes() {
            assertEquals(envelope("ML-KEM-768", (byte) 5), envelope("ML-KEM-768", (byte) 5));
            assertEquals(envelope("ML-KEM-768", (byte) 5).hashCode(), envelope("ML-KEM-768", (byte) 5).hashCode());
        }

        @Test
        void a_different_header_or_different_bytes_make_a_different_envelope() {
            assertNotEquals(envelope("ML-KEM-768", (byte) 5), envelope("RSA-OAEP-3072", (byte) 5));
            assertNotEquals(envelope("ML-KEM-768", (byte) 5), envelope("ML-KEM-768", (byte) 6));
        }
    }

    @Nested
    class Comparing_wrapped_keys {

        @Test
        void compares_field_names_and_bytes_in_any_order() {
            Map<String, byte[]> first = new LinkedHashMap<>();
            first.put("wrappedKey", new byte[] {1});
            first.put("kemCt", new byte[] {2});
            Map<String, byte[]> second = new LinkedHashMap<>();
            second.put("kemCt", new byte[] {2});
            second.put("wrappedKey", new byte[] {1});

            assertEquals(new WrappedDek(first), new WrappedDek(second));
            assertEquals(new WrappedDek(first).hashCode(), new WrappedDek(second).hashCode());
            assertNotEquals(new WrappedDek(first), WrappedDek.of("wrappedKey", new byte[] {1}));
            assertNotEquals(WrappedDek.of("wrappedKey", new byte[] {1}), WrappedDek.of("wrappedKey", new byte[] {9}));
        }
    }

    @Nested
    class Printing {

        @Test
        void shows_names_and_sizes_but_never_the_bytes() {
            String text = new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", new byte[12], new byte[] {42, 42},
                    WrappedDek.of("wrappedKey", new byte[] {42})).toString();

            assertTrue(text.contains("alg=ML-KEM-768"));
            assertTrue(text.contains("ciphertext=2 bytes"));
            assertTrue(text.contains("wrappedKey=1 bytes"));
            assertFalse(text.contains("42"));
        }
    }
}
