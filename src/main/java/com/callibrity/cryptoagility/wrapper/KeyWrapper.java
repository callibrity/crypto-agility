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
import javax.crypto.SecretKey;

/**
 * The seam. Swap the implementation, never the call sites.
 *
 * <p>Everything that depends on the choice of algorithm lives behind these three methods. To
 * support a new algorithm, write one more implementation and register it; nothing that seals or
 * opens an envelope has to change.
 */
public interface KeyWrapper {

  /** The name written into every envelope this wrapper produces. */
  String algId();

  WrappedDek wrap(SecretKey dek) throws GeneralSecurityException;

  SecretKey unwrap(WrappedDek w) throws GeneralSecurityException;
}
