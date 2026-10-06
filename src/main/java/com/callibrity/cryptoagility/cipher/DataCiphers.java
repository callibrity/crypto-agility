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

import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Every data cipher this system can read, keyed by the name envelopes carry. */
public final class DataCiphers {

  /** What new data is encrypted with unless asked otherwise. */
  public static final DataCipher DEFAULT = AesGcm.INSTANCE;

  private static final Map<String, DataCipher> CIPHERS = new LinkedHashMap<>();

  static {
    register(AesGcm.INSTANCE);
    register(ChaCha20Poly1305.INSTANCE);
  }

  private DataCiphers() {}

  private static void register(DataCipher cipher) {
    CIPHERS.put(cipher.algId(), cipher);
  }

  public static boolean contains(String algId) {
    return CIPHERS.containsKey(algId);
  }

  public static DataCipher get(String algId) throws UnknownAlgorithmException {
    DataCipher cipher = CIPHERS.get(algId);
    if (cipher == null) {
      throw new UnknownAlgorithmException(
          "no data cipher called " + algId + " (known: " + CIPHERS.keySet() + ")");
    }
    return cipher;
  }

  public static List<DataCipher> all() {
    return List.copyOf(CIPHERS.values());
  }
}
