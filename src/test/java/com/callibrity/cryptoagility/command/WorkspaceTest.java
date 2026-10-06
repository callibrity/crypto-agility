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
package com.callibrity.cryptoagility.command;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.callibrity.cryptoagility.kms.KeyMetadata;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class WorkspaceTest {

  @TempDir Path dataDir;

  @Nested
  class Choosing_the_key_for_new_data {

    @Test
    void creates_one_the_first_time_and_reuses_it_after()
        throws GeneralSecurityException, IOException {
      var ws = new Workspace(dataDir);

      KeyMetadata first = ws.currentKey("ML-KEM-768");
      KeyMetadata again = ws.currentKey("ML-KEM-768");

      assertEquals(first.keyId(), again.keyId());
      assertEquals(1, ws.kms().listKeys().size());
    }

    @Test
    void a_disabled_key_is_passed_over_for_a_new_one()
        throws GeneralSecurityException, IOException {
      var ws = new Workspace(dataDir);
      KeyMetadata old = ws.currentKey("ML-KEM-768");
      ws.kms().disableKey(old.keyId());

      KeyMetadata replacement = ws.currentKey("ML-KEM-768");

      assertNotEquals(old.keyId(), replacement.keyId());
    }
  }
}
