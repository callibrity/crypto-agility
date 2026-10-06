/*
 * Copyright © 2026 Callibrity, Inc. (contactus@callibrity.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.callibrity.cryptoagility.cipher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class EncryptedTest {

  @Nested
  class Comparing {

    @Test
    void equal_bytes_make_equal_values() {
      var first = new Encrypted(new byte[] {1, 2}, new byte[] {3, 4});
      var second = new Encrypted(new byte[] {1, 2}, new byte[] {3, 4});

      assertEquals(first, second);
      assertEquals(first.hashCode(), second.hashCode());
    }

    @Test
    void different_bytes_make_different_values() {
      assertNotEquals(
          new Encrypted(new byte[] {1}, new byte[] {2}),
          new Encrypted(new byte[] {1}, new byte[] {9}));
    }
  }

  @Nested
  class Printing {

    @Test
    void shows_sizes_and_never_the_bytes() {
      String text = new Encrypted(new byte[12], new byte[] {42, 42, 42}).toString();

      assertEquals("Encrypted[nonce=12 bytes, ciphertext=3 bytes]", text);
      assertFalse(text.contains("42"));
    }
  }
}
