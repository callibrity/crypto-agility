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

import com.callibrity.cryptoagility.cbom.Inventoried;
import com.callibrity.cryptoagility.cipher.DataKeySpec;
import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import com.callibrity.cryptoagility.store.KeyValueFile;
import com.callibrity.cryptoagility.wrapper.AesGcmWrapper;
import com.callibrity.cryptoagility.wrapper.EcdhWrapper;
import com.callibrity.cryptoagility.wrapper.HqcWrapper;
import com.callibrity.cryptoagility.wrapper.HybridWrapper;
import com.callibrity.cryptoagility.wrapper.KeyWrapper;
import com.callibrity.cryptoagility.wrapper.MlKemWrapper;
import com.callibrity.cryptoagility.wrapper.RsaWrapper;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * A stand-in KMS that keeps its keys in files, one per key under its directory. It behaves like the
 * real thing from the outside: callers name a key by id and never see key material. Inside, the
 * KeyWrapper classes do the work.
 *
 * <p>DEMO ONLY. A real KMS keeps keys in hardware and never writes them out. Here the private keys
 * sit unencrypted on disk, so that you can look at them.
 */
public final class LocalKms implements KeyManagementService {

  private static final String SUFFIX = ".key";
  private static final String ALGORITHM = "algorithm";
  private static final String CREATED = "created";
  private static final String STATE = "state";
  private static final String ENABLED = "enabled";
  private static final String DISABLED = "disabled";
  private static final SecureRandom RNG = new SecureRandom();

  // BouncyCastle supplies algorithms the JDK lacks: BCPQC serves HQC, and BC serves others you
  // might add, such as FrodoKEM. Both go in at start-up, after the JDK's own providers, so that a
  // stored key can be decoded before anything else has touched BouncyCastle.
  static {
    Security.addProvider(new BouncyCastleProvider());
    Security.addProvider(new BouncyCastlePQCProvider());
  }

  private final Path dir;
  private final Map<String, KeyType> types = new LinkedHashMap<>();
  private final Map<String, KeyWrapper> loaded = new HashMap<>();
  private final Map<String, AlgorithmInfo> described = new HashMap<>();

  public LocalKms(Path dir) {
    this.dir = dir;
  }

  /**
   * Every algorithm this KMS offers. Supporting a new one is a KeyWrapper class plus one register
   * line here.
   */
  public static LocalKms withStandardAlgorithms(Path dir) {
    var kms = new LocalKms(dir);
    kms.register(KeyTypes.keyPair(RsaWrapper.ALG_ID, RsaWrapper::newKeyPair, RsaWrapper::new));
    kms.register(KeyTypes.keyPair(EcdhWrapper.ALG_ID, EcdhWrapper::newKeyPair, EcdhWrapper::new));
    kms.register(
        KeyTypes.secretKey(AesGcmWrapper.ALG_ID, AesGcmWrapper::newKey, AesGcmWrapper::new));
    for (MlKemWrapper.ParameterSet set : MlKemWrapper.ParameterSet.values()) {
      kms.register(
          KeyTypes.keyPair(
              set.algId(), () -> MlKemWrapper.newKeyPair(set), kp -> new MlKemWrapper(set, kp)));
    }
    kms.register(
        KeyTypes.twoKeyPairs(
            HybridWrapper.ALG_ID,
            HybridWrapper::newX25519KeyPair,
            MlKemWrapper::newKeyPair,
            HybridWrapper::new));
    for (HqcWrapper.ParameterSet set : HqcWrapper.ParameterSet.values()) {
      kms.register(
          KeyTypes.keyPair(
              set.algId(), () -> HqcWrapper.newKeyPair(set), kp -> new HqcWrapper(set, kp)));
    }
    return kms;
  }

  public LocalKms register(KeyType type) {
    types.put(type.algorithm(), type);
    return this;
  }

  @Override
  public List<String> algorithms() {
    return List.copyOf(types.keySet());
  }

  // The facts come from the wrapper itself, so describing an algorithm builds one with a throwaway
  // key.
  @Override
  public AlgorithmInfo describeAlgorithm(String algorithm) throws GeneralSecurityException {
    AlgorithmInfo info = described.get(algorithm);
    if (info == null) {
      KeyType type = type(algorithm);
      KeyWrapper sample = type.wrapper(type.newKeyMaterial());
      info =
          sample instanceof Inventoried inventoried
              ? new AlgorithmInfo(algorithm, inventoried.facts(), inventoried.provider())
              : new AlgorithmInfo(algorithm, null, null);
      described.put(algorithm, info);
    }
    return info;
  }

  @Override
  public KeyMetadata createKey(String algorithm) throws GeneralSecurityException, IOException {
    KeyType type = type(algorithm);
    String keyId = newKeyId();
    Instant created = Instant.now();
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put(ALGORITHM, algorithm);
    fields.put(CREATED, created.toString());
    fields.put(STATE, ENABLED);
    fields.putAll(type.newKeyMaterial());
    KeyValueFile.write(file(keyId), fields);
    return new KeyMetadata(keyId, algorithm, created, true);
  }

  @Override
  public KeyMetadata describeKey(String keyId) throws GeneralSecurityException, IOException {
    return metadata(keyId, read(keyId));
  }

  /** Every key, oldest first. */
  @Override
  public List<KeyMetadata> listKeys() throws IOException {
    List<KeyMetadata> keys = new ArrayList<>();
    if (Files.isDirectory(dir)) {
      try (Stream<Path> files = Files.list(dir)) {
        for (Path file : files.filter(f -> f.getFileName().toString().endsWith(SUFFIX)).toList()) {
          String keyId = file.getFileName().toString().replace(SUFFIX, "");
          Map<String, String> fields = KeyValueFile.read(file);
          keys.add(
              new KeyMetadata(keyId, fields.get(ALGORITHM), created(fields), isEnabled(fields)));
        }
      }
    }
    keys.sort(Comparator.comparing(KeyMetadata::created).thenComparing(KeyMetadata::keyId));
    return keys;
  }

  @Override
  public DataKey generateDataKey(String keyId, DataKeySpec spec, byte[] encryptionContext)
      throws GeneralSecurityException, IOException {
    KeyMetadata key = describeKey(keyId);
    byte[] bytes = new byte[spec.bytes()];
    try {
      RNG.nextBytes(bytes);
      SecretKey dataKey = new SecretKeySpec(bytes, spec.algorithm());
      return new DataKey(
          dataKey, keyId, key.algorithm(), engine(key).wrap(dataKey, encryptionContext));
    } finally {
      // SecretKeySpec keeps its own copy; this one is wiped.
      Arrays.fill(bytes, (byte) 0);
    }
  }

  @Override
  public SecretKey decryptDataKey(String keyId, WrappedDek wrapped, byte[] encryptionContext)
      throws GeneralSecurityException, IOException {
    return engine(describeKey(keyId)).unwrap(wrapped, encryptionContext);
  }

  // The plaintext data key exists only inside this method: the caller gets back a wrapped key and
  // nothing else.
  @Override
  public WrappedDek reEncrypt(
      String keyId,
      WrappedDek wrapped,
      byte[] encryptionContext,
      String newKeyId,
      byte[] newEncryptionContext)
      throws GeneralSecurityException, IOException {
    SecretKey dataKey = decryptDataKey(keyId, wrapped, encryptionContext);
    return engine(describeKey(newKeyId)).wrap(dataKey, newEncryptionContext);
  }

  @Override
  public void disableKey(String keyId) throws GeneralSecurityException, IOException {
    setState(keyId, DISABLED);
  }

  @Override
  public void enableKey(String keyId) throws GeneralSecurityException, IOException {
    setState(keyId, ENABLED);
  }

  private KeyType type(String algorithm) throws UnknownAlgorithmException {
    KeyType type = types.get(algorithm);
    if (type == null) {
      throw new UnknownAlgorithmException(
          "the KMS has no algorithm " + algorithm + " (it offers: " + types.keySet() + ")");
    }
    return type;
  }

  // Loaded once per key and kept, the way a real KMS keeps its keys ready in hardware.
  private KeyWrapper engine(KeyMetadata key) throws GeneralSecurityException, IOException {
    if (!key.enabled()) {
      throw new KeyDisabledException("key " + key.keyId() + " is disabled");
    }
    KeyWrapper engine = loaded.get(key.keyId());
    if (engine == null) {
      engine = type(key.algorithm()).wrapper(read(key.keyId()));
      loaded.put(key.keyId(), engine);
    }
    return engine;
  }

  private Map<String, String> read(String keyId) throws GeneralSecurityException, IOException {
    Path file = file(keyId);
    if (!Files.isRegularFile(file)) {
      throw new UnknownKeyException("the KMS has no key " + keyId);
    }
    return KeyValueFile.read(file);
  }

  private void setState(String keyId, String state) throws GeneralSecurityException, IOException {
    Map<String, String> fields = read(keyId);
    fields.put(STATE, state);
    KeyValueFile.write(file(keyId), fields);
  }

  private KeyMetadata metadata(String keyId, Map<String, String> fields) {
    return new KeyMetadata(keyId, fields.get(ALGORITHM), created(fields), isEnabled(fields));
  }

  private static Instant created(Map<String, String> fields) {
    String created = fields.get(CREATED);
    return created == null ? Instant.EPOCH : Instant.parse(created);
  }

  private static boolean isEnabled(Map<String, String> fields) {
    return ENABLED.equals(fields.get(STATE));
  }

  private String newKeyId() {
    String keyId;
    do {
      byte[] random = new byte[3];
      RNG.nextBytes(random);
      keyId = "key-" + HexFormat.of().formatHex(random);
    } while (Files.exists(file(keyId)));
    return keyId;
  }

  private Path file(String keyId) {
    return dir.resolve(keyId + SUFFIX);
  }
}
