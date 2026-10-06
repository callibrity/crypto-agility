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
package com.callibrity.cryptoagility.cbom;

/**
 * An algorithm that can describe itself for a cryptographic inventory (a CBOM).
 *
 * <p>Kept apart from KeyWrapper on purpose. The seam stays at three methods, and the facts about an
 * algorithm still live in the one class that implements it.
 */
public interface Inventoried {

  AlgorithmFacts facts();

  /**
   * The JCA provider that does the work, as resolved on this JVM. Usually one that ships with the
   * JDK, such as SunJCE, or BouncyCastle's BCPQC.
   */
  String provider();
}
