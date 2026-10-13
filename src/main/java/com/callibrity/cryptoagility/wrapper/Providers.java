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

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Finds out which JCA providers actually serve an algorithm on this JVM. For a KEM the JDK only
 * picks the provider once it sees the key, so ask with the key.
 */
final class Providers {

  /** Looks up the name of the provider behind one piece of an algorithm. */
  @FunctionalInterface
  interface Lookup {
    String name() throws GeneralSecurityException;
  }

  private Providers() {}

  /** The distinct provider names, joined with "+", or "unavailable" if one cannot be found. */
  static String names(Lookup... lookups) {
    try {
      String[] names = new String[lookups.length];
      for (int i = 0; i < lookups.length; i++) {
        names[i] = lookups[i].name();
      }
      return Arrays.stream(names).distinct().collect(Collectors.joining("+"));
    } catch (GeneralSecurityException _) {
      return "unavailable";
    }
  }
}
