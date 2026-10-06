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
package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.wrapper.KeyWrapper;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * One algorithm, as LocalKms needs to know it: how to make key material for a new key, and how to
 * turn stored key material back into the KeyWrapper that does the work. Supporting a new algorithm
 * is a KeyWrapper class plus one of these, which KeyTypes makes for you.
 */
public interface KeyType {

  String algorithm();

  /** New key material, as named text fields ready to store. */
  Map<String, String> newKeyMaterial() throws GeneralSecurityException;

  KeyWrapper wrapper(Map<String, String> material) throws GeneralSecurityException;
}
