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
package com.callibrity.cryptoagility.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Plain "name=value" text files, one field per line, so stored state is easy to open and read. */
public final class KeyValueFile {

  private KeyValueFile() {}

  public static Map<String, String> read(Path file) throws IOException {
    Map<String, String> fields = new LinkedHashMap<>();
    for (String line : Files.readAllLines(file)) {
      int eq = line.indexOf('=');
      if (line.isBlank() || line.startsWith("#") || eq < 0) {
        continue;
      }
      fields.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
    }
    return fields;
  }

  public static void write(Path file, Map<String, String> fields) throws IOException {
    List<String> lines = new ArrayList<>();
    fields.forEach((name, value) -> lines.add(name + "=" + value));
    Files.createDirectories(file.getParent());
    Files.write(file, lines);
  }

  public static String encode(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  public static byte[] decode(Path file, String field, String value) throws IOException {
    if (value == null) {
      throw new IOException(file + " has no '" + field + "' field");
    }
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      throw new IOException(file + " has a '" + field + "' field that is not valid Base64", e);
    }
  }
}
