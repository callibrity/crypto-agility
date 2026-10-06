package com.callibrity.cryptoagility.cipher;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class SealedTest {

    @Nested
    class Comparing {

        @Test
        void equal_bytes_make_equal_values() {
            var first = new Sealed(new byte[] {1, 2}, new byte[] {3, 4});
            var second = new Sealed(new byte[] {1, 2}, new byte[] {3, 4});

            assertEquals(first, second);
            assertEquals(first.hashCode(), second.hashCode());
        }

        @Test
        void different_bytes_make_different_values() {
            assertNotEquals(new Sealed(new byte[] {1}, new byte[] {2}), new Sealed(new byte[] {1}, new byte[] {9}));
        }
    }

    @Nested
    class Printing {

        @Test
        void shows_sizes_and_never_the_bytes() {
            String text = new Sealed(new byte[12], new byte[] {42, 42, 42}).toString();

            assertEquals("Sealed[nonce=12 bytes, ciphertext=3 bytes]", text);
            assertFalse(text.contains("42"));
        }
    }
}
