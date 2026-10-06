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

import com.callibrity.cryptoagility.kms.KeyManagementService;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.kms.LocalKms;
import com.callibrity.cryptoagility.store.EnvelopeStore;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Comparator;

/**
 * What the commands share: the envelopes on disk and the KMS that holds the keys. Everything lives
 * under one data directory.
 */
public final class Workspace {

  private final Path dataDir;
  private final EnvelopeStore envelopes;
  private final KeyManagementService kms;

  public Workspace(Path dataDir) {
    this(dataDir, LocalKms.withStandardAlgorithms(dataDir.resolve("kms")));
  }

  public Workspace(Path dataDir, KeyManagementService kms) {
    this.dataDir = dataDir;
    this.envelopes = new EnvelopeStore(dataDir.resolve("envelopes"));
    this.kms = kms;
  }

  public Path dataDir() {
    return dataDir;
  }

  /** The stored envelopes. Looking at them needs no keys. */
  public EnvelopeStore envelopes() {
    return envelopes;
  }

  public KeyManagementService kms() {
    return kms;
  }

  /**
   * The key new data is wrapped with for an algorithm: the newest enabled one, created in the KMS
   * the first time the algorithm is used.
   */
  public KeyMetadata currentKey(String algorithm) throws GeneralSecurityException, IOException {
    var newest =
        kms.listKeys().stream()
            .filter(key -> key.enabled() && key.algorithm().equals(algorithm))
            .max(Comparator.comparing(KeyMetadata::created).thenComparing(KeyMetadata::keyId));
    return newest.isPresent() ? newest.get() : kms.createKey(algorithm);
  }
}
