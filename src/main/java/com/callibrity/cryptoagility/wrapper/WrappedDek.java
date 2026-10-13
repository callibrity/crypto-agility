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

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * A wrapped data key, as whatever named fields the wrapping algorithm needs.
 *
 * <p>The envelope does not know or care what the fields are. RSA produces one (the encrypted key).
 * A KEM produces three. The next algorithm can produce something else, and nothing that stores or
 * carries envelopes has to change. Only the wrapper that wrote the fields reads them back.
 *
 * <p>Every field's bytes are copied on the way in and on the way out, so no caller can change them.
 */
public record WrappedDek(Map<String, byte[]> fields) {

  public WrappedDek {
    Objects.requireNonNull(fields, "fields");
    Map<String, byte[]> copy = new LinkedHashMap<>();
    for (Map.Entry<String, byte[]> field : fields.entrySet()) {
      String name = Objects.requireNonNull(field.getKey(), "field name");
      copy.put(name, Objects.requireNonNull(field.getValue(), name).clone());
    }
    fields = Collections.unmodifiableMap(copy);
  }

  public static WrappedDek of(String name, byte[] value) {
    return new WrappedDek(Map.of(name, value));
  }

  /** A copy of the fields; changing it, or the bytes in it, does not change this wrapped key. */
  @Override
  public Map<String, byte[]> fields() {
    Map<String, byte[]> copy = new LinkedHashMap<>();
    fields.forEach((name, value) -> copy.put(name, value.clone()));
    return Collections.unmodifiableMap(copy);
  }

  /**
   * Returns a field the named algorithm cannot do without, or fails saying which one is missing.
   */
  public byte[] require(String name, String algId) throws InvalidKeyException {
    byte[] value = fields.get(name);
    if (value == null) {
      throw new InvalidKeyException(
          "wrapped key has no " + name + " field, so it was not wrapped with " + algId);
    }
    return value.clone();
  }

  // A map of arrays compares its values by identity, so equality and hashing are spelled out to
  // compare bytes.
  @Override
  public boolean equals(Object other) {
    if (!(other instanceof WrappedDek(Map<String, byte[]> otherFields))
        || !fields.keySet().equals(otherFields.keySet())) {
      return false;
    }
    for (Map.Entry<String, byte[]> field : fields.entrySet()) {
      if (!Arrays.equals(field.getValue(), otherFields.get(field.getKey()))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    int hash = 0;
    for (Map.Entry<String, byte[]> field : fields.entrySet()) {
      hash += field.getKey().hashCode() ^ Arrays.hashCode(field.getValue());
    }
    return hash;
  }

  /** The field names and their sizes, never the bytes themselves. */
  @Override
  public String toString() {
    var out = new StringJoiner(", ", "WrappedDek[", "]");
    fields.forEach((name, value) -> out.add(name + "=" + value.length + " bytes"));
    return out.toString();
  }
}
