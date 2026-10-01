package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeViewTest {

    private static final Envelope DIRECT =
            new Envelope("RSA-OAEP-3072", new byte[12], new byte[34], new byte[384], null, null);
    private static final Envelope KEM =
            new Envelope("ML-KEM-768", new byte[12], new byte[34], new byte[48], new byte[1088], new byte[12]);

    @Nested
    class For_any_envelope {

        @Test
        void draws_a_closed_box_with_every_line_the_same_width() {
            List<String> lines = EnvelopeView.render("record-0001", KEM).lines().toList();

            assertEquals(1, lines.stream().map(String::length).distinct().count());
            assertTrue(lines.getFirst().startsWith("┌") && lines.getFirst().endsWith("┐"));
            assertTrue(lines.getLast().startsWith("└") && lines.getLast().endsWith("┘"));
        }

        @Test
        void names_the_record_and_its_algorithm() {
            String view = EnvelopeView.render("record-0001", KEM);

            assertTrue(view.contains("record-0001"));
            assertTrue(view.contains("ML-KEM-768"));
        }

        @Test
        void reports_the_data_size_without_the_gcm_tag() {
            String view = EnvelopeView.render("record-0001", DIRECT);

            assertTrue(view.contains("18 bytes of data + 16-byte tag"));
        }

        @Test
        void says_so_when_the_algorithm_is_missing() {
            var anonymous = new Envelope(null, new byte[12], new byte[34], new byte[384], null, null);

            assertTrue(EnvelopeView.render("record-0001", anonymous).contains("(none)"));
        }
    }

    @Nested
    class For_a_kem_wrapped_key {

        @Test
        void shows_the_kem_ciphertext_and_wrap_nonce() {
            String view = EnvelopeView.render("record-0001", KEM);

            assertTrue(view.contains("kemCt"));
            assertTrue(view.contains("1088 bytes"));
            assertTrue(view.contains("wrapNonce"));
        }
    }

    @Nested
    class For_a_directly_wrapped_key {

        @Test
        void leaves_out_the_kem_rows() {
            String view = EnvelopeView.render("record-0001", DIRECT);

            assertFalse(view.contains("kemCt"));
            assertFalse(view.contains("wrapNonce"));
            assertTrue(view.contains("384 bytes"));
        }
    }
}
