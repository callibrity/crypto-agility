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

/**
 * What kind of data key to generate: the JCA key algorithm and its size. A KMS only needs this to
 * produce the right number of random bytes; it never sees the data, so it does not care which
 * cipher will use the key.
 */
public record DataKeySpec(String algorithm, int bits) {

  public static final DataKeySpec AES_256 = new DataKeySpec("AES", 256);
  public static final DataKeySpec CHACHA20 = new DataKeySpec("ChaCha20", 256);

  public int bytes() {
    return bits / 8;
  }
}
