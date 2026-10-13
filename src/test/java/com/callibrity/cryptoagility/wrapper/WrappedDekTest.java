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
package com.callibrity.cryptoagility.wrapper;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class WrappedDekTest {

  @Nested
  class Guarding_its_bytes {

    @Test
    void changing_the_map_or_arrays_it_was_given_does_not_change_it() throws InvalidKeyException {
      byte[] value = {1, 2};
      Map<String, byte[]> fields = new LinkedHashMap<>();
      fields.put("wrappedKey", value);
      var wrapped = new WrappedDek(fields);

      value[0] = 9;
      fields.put("wrappedKey", new byte[] {9, 9});

      assertArrayEquals(new byte[] {1, 2}, wrapped.require("wrappedKey", "RSA-OAEP-3072"));
    }

    @Test
    void changing_an_array_from_require_does_not_change_it() throws InvalidKeyException {
      var wrapped = WrappedDek.of("wrappedKey", new byte[] {1, 2});

      wrapped.require("wrappedKey", "RSA-OAEP-3072")[0] = 9;

      assertArrayEquals(new byte[] {1, 2}, wrapped.require("wrappedKey", "RSA-OAEP-3072"));
    }

    @Test
    void changing_an_array_from_fields_does_not_change_it() {
      var wrapped = WrappedDek.of("wrappedKey", new byte[] {1, 2});

      wrapped.fields().get("wrappedKey")[0] = 9;

      assertArrayEquals(new byte[] {1, 2}, wrapped.fields().get("wrappedKey"));
    }

    @Test
    void the_fields_it_hands_out_cannot_be_changed() {
      Map<String, byte[]> fields = WrappedDek.of("wrappedKey", new byte[] {1, 2}).fields();

      assertThrows(UnsupportedOperationException.class, () -> fields.put("kemCt", new byte[] {3}));
    }

    @Test
    void refuses_missing_fields_names_or_values() {
      Map<String, byte[]> nullName = new HashMap<>();
      nullName.put(null, new byte[] {1});
      Map<String, byte[]> nullValue = new HashMap<>();
      nullValue.put("wrappedKey", null);

      assertThrows(NullPointerException.class, () -> new WrappedDek(null));
      assertThrows(NullPointerException.class, () -> new WrappedDek(nullName));
      assertThrows(NullPointerException.class, () -> new WrappedDek(nullValue));
    }
  }
}
