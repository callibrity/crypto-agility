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

import java.util.Arrays;

/**
 * What an authenticated cipher produces: the nonce it used, and the ciphertext with its tag. Two
 * are equal when their bytes are, and toString shows sizes rather than bytes.
 */
public record Encrypted(byte[] nonce, byte[] ciphertext) {

  @Override
  public boolean equals(Object other) {
    return other instanceof Encrypted that
        && Arrays.equals(nonce, that.nonce)
        && Arrays.equals(ciphertext, that.ciphertext);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(nonce) + Arrays.hashCode(ciphertext);
  }

  @Override
  public String toString() {
    return "Encrypted[nonce=" + size(nonce) + ", ciphertext=" + size(ciphertext) + "]";
  }

  private static String size(byte[] bytes) {
    return bytes == null ? "null" : bytes.length + " bytes";
  }
}
