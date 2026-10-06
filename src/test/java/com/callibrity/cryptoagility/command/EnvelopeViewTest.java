package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EnvelopeViewTest {

    private static final Envelope DIRECT = new Envelope("RSA-OAEP-3072", "key-000001", "AES-256-GCM", new byte[12], new byte[34],
            WrappedDek.of("wrappedKey", new byte[384]));
    private static final Envelope KEM = new Envelope("ML-KEM-768", "key-000001", "AES-256-GCM", new byte[12], new byte[34], new WrappedDek(kemFields()));

    private static Map<String, byte[]> kemFields() {
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put("wrappedKey", new byte[48]);
        fields.put("kemCt", new byte[1088]);
        fields.put("wrapNonce", new byte[12]);
        return fields;
    }

    @Nested
    class For_any_envelope {

        @Test
        void draws_a_closed_envelope_with_every_line_the_same_width() {
            List<String> lines = EnvelopeView.render("record-0001", KEM).lines().toList();

            assertEquals(1, lines.stream().map(String::length).distinct().count());
            assertTrue(lines.get(1).startsWith("╭") && lines.get(1).endsWith("╮"));
            assertTrue(lines.getLast().startsWith("╰") && lines.getLast().endsWith("╯"));
        }

        @Test
        void keeps_its_shape_when_a_field_name_is_long() {
            var novel = new Envelope("SOMETHING-NEW", "key-000001", "AES-256-GCM", new byte[12], new byte[34],
                    WrappedDek.of("aVeryLongFieldNameIndeed", new byte[4]));

            List<String> lines = EnvelopeView.render("record-0001", novel).lines().toList();

            assertEquals(1, lines.stream().map(String::length).distinct().count());
        }

        @Test
        void keeps_its_shape_when_the_algorithm_name_is_long() {
            var odd = new Envelope("A-VERY-LONG-ALGORITHM-NAME-SOMEONE-TYPED-IN-BY-HAND", "key-000001", "AES-256-GCM", new byte[12], new byte[34],
                    WrappedDek.of("wrappedKey", new byte[4]));

            List<String> lines = EnvelopeView.render("record-0001", odd).lines().toList();

            assertEquals(1, lines.stream().map(String::length).distinct().count());
        }

        @Test
        void totals_the_bytes_stored() {
            String firstLine = EnvelopeView.render("record-0001", KEM).lines().findFirst().orElseThrow();

            assertTrue(firstLine.endsWith((12 + 34 + 48 + 1088 + 12) + " bytes"));
        }

        @Test
        void points_from_the_wrapped_key_to_the_data_it_opens() {
            List<String> lines = EnvelopeView.render("record-0001", KEM).lines().toList();
            String arrow = lines.stream().filter(line -> line.contains("▼")).findFirst().orElseThrow();
            String above = lines.get(lines.indexOf(arrow) - 1);

            assertEquals(above.indexOf('┬'), arrow.indexOf('▼'));
        }

        @Test
        void is_plain_text_unless_colour_is_turned_on() {
            assertFalse(EnvelopeView.render("record-0001", KEM).contains("\u001b"));
        }

        @Test
        void colour_changes_nothing_but_the_colour() {
            String plain = EnvelopeView.render("record-0001", KEM);
            Paint.enable(true);
            try {
                String coloured = EnvelopeView.render("record-0001", KEM);

                assertTrue(coloured.contains("\u001b["));
                assertEquals(plain, coloured.replaceAll("\u001b\\[[0-9;]*m", ""));
            } finally {
                Paint.enable(false);
            }
        }

        @Test
        void names_the_record_and_its_algorithm() {
            String view = EnvelopeView.render("record-0001", KEM);

            assertTrue(view.contains("record-0001"));
            assertTrue(view.contains("ML-KEM-768"));
        }

        @Test
        void draws_a_field_it_has_never_heard_of() {
            var novel = new Envelope("SOMETHING-NEW", "key-000001", "AES-256-GCM", new byte[12], new byte[34], WrappedDek.of("keyVersion", new byte[4]));

            assertTrue(EnvelopeView.render("record-0001", novel).contains("keyVersion"));
        }

        @Test
        void reports_the_data_size_without_the_gcm_tag() {
            String view = EnvelopeView.render("record-0001", DIRECT);

            assertTrue(view.contains("18 bytes of data + 16-byte tag"));
        }

        @Test
        void says_so_when_the_algorithm_is_missing() {
            var anonymous = new Envelope(null, "key-000001", "AES-256-GCM", new byte[12], new byte[34], DIRECT.wrappedDek());

            assertTrue(EnvelopeView.render("record-0001", anonymous).contains("(none)"));
        }
    }

    @Nested
    class For_a_wrapped_key_with_several_fields {

        @Test
        void draws_a_row_for_each_field() {
            String view = EnvelopeView.render("record-0001", KEM);

            assertTrue(view.contains("kemCt"));
            assertTrue(view.contains("1088 bytes"));
            assertTrue(view.contains("wrapNonce"));
        }
    }

    @Nested
    class Comparing_field_sizes {

        private long blocksOn(String view, String field) {
            String row = view.lines().filter(line -> line.contains(field + " ")).findFirst().orElseThrow();
            return row.chars().filter(c -> c == '█').count();
        }

        @Test
        void a_bigger_field_gets_a_longer_bar() {
            String view = EnvelopeView.render("record-0001", KEM);

            assertEquals(17, blocksOn(view, "kemCt"));
            assertEquals(0, blocksOn(view, "wrappedKey"));
        }

        @Test
        void an_rsa_wrapped_key_is_six_blocks() {
            assertEquals(6, blocksOn(EnvelopeView.render("record-0001", DIRECT), "wrappedKey"));
        }

        @Test
        void a_field_too_big_to_draw_is_marked_rather_than_overflowing() {
            var huge = new Envelope("RSA-OAEP-3072", "key-000001", "AES-256-GCM", new byte[12], new byte[5000], DIRECT.wrappedDek());
            List<String> lines = EnvelopeView.render("record-0001", huge).lines().toList();

            assertEquals(1, lines.stream().map(String::length).distinct().count());
            assertTrue(lines.stream().anyMatch(line -> line.contains("█+")));
        }
    }

    @Nested
    class For_a_wrapped_key_with_one_field {

        @Test
        void draws_only_that_row() {
            String view = EnvelopeView.render("record-0001", DIRECT);

            assertFalse(view.contains("kemCt"));
            assertFalse(view.contains("wrapNonce"));
            assertTrue(view.contains("384 bytes"));
        }
    }
}
