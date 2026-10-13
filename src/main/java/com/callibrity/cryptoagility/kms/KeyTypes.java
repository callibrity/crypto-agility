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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Ready-made KeyTypes for the usual shapes of key: one key pair, two key pairs, or one secret key.
 */
public final class KeyTypes {

  /** Makes a new key pair. */
  @FunctionalInterface
  public interface KeyPairSource {
    KeyPair generate() throws GeneralSecurityException;
  }

  /** Builds a wrapper around a key pair. */
  @FunctionalInterface
  public interface KeyPairEngine {
    KeyWrapper wrapper(KeyPair keyPair) throws GeneralSecurityException;
  }

  /** Builds a wrapper around two key pairs, for a hybrid. */
  @FunctionalInterface
  public interface TwoKeyPairEngine {
    KeyWrapper wrapper(KeyPair first, KeyPair second) throws GeneralSecurityException;
  }

  /** Makes a new secret key. */
  @FunctionalInterface
  public interface SecretKeySource {
    SecretKey generate() throws GeneralSecurityException;
  }

  /** Builds a wrapper around a secret key. */
  @FunctionalInterface
  public interface SecretKeyEngine {
    KeyWrapper wrapper(SecretKey key) throws GeneralSecurityException;
  }

  private KeyTypes() {}

  public static KeyType keyPair(String algorithm, KeyPairSource source, KeyPairEngine engine) {
    return new KeyType() {
      @Override
      public String algorithm() {
        return algorithm;
      }

      @Override
      public Map<String, String> newKeyMaterial() throws GeneralSecurityException {
        Map<String, String> material = new LinkedHashMap<>();
        putKeyPair(material, "", source.generate());
        return material;
      }

      @Override
      public KeyWrapper wrapper(Map<String, String> material) throws GeneralSecurityException {
        return engine.wrapper(keyPair(material, ""));
      }
    };
  }

  public static KeyType twoKeyPairs(
      String algorithm, KeyPairSource first, KeyPairSource second, TwoKeyPairEngine engine) {
    return new KeyType() {
      @Override
      public String algorithm() {
        return algorithm;
      }

      @Override
      public Map<String, String> newKeyMaterial() throws GeneralSecurityException {
        Map<String, String> material = new LinkedHashMap<>();
        putKeyPair(material, "first.", first.generate());
        putKeyPair(material, "second.", second.generate());
        return material;
      }

      @Override
      public KeyWrapper wrapper(Map<String, String> material) throws GeneralSecurityException {
        return engine.wrapper(keyPair(material, "first."), keyPair(material, "second."));
      }
    };
  }

  public static KeyType secretKey(
      String algorithm, SecretKeySource source, SecretKeyEngine engine) {
    return new KeyType() {
      @Override
      public String algorithm() {
        return algorithm;
      }

      @Override
      public Map<String, String> newKeyMaterial() throws GeneralSecurityException {
        SecretKey key = source.generate();
        Map<String, String> material = new LinkedHashMap<>();
        material.put("keyAlgorithm", key.getAlgorithm());
        material.put("key", encodeAndWipe(key.getEncoded()));
        return material;
      }

      @Override
      public KeyWrapper wrapper(Map<String, String> material) throws GeneralSecurityException {
        String keyAlgorithm = field(material, "keyAlgorithm");
        byte[] key = decode(material, "key");
        try {
          return engine.wrapper(new SecretKeySpec(key, keyAlgorithm));
        } finally {
          Arrays.fill(key, (byte) 0);
        }
      }
    };
  }

  private static void putKeyPair(Map<String, String> material, String prefix, KeyPair keyPair) {
    material.put(prefix + "keyAlgorithm", keyPair.getPublic().getAlgorithm());
    material.put(
        prefix + "public", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    material.put(prefix + "private", encodeAndWipe(keyPair.getPrivate().getEncoded()));
  }

  private static KeyPair keyPair(Map<String, String> material, String prefix)
      throws GeneralSecurityException {
    var factory = KeyFactory.getInstance(field(material, prefix + "keyAlgorithm"));
    var publicKey =
        factory.generatePublic(new X509EncodedKeySpec(decode(material, prefix + "public")));
    byte[] privateKey = decode(material, prefix + "private");
    try {
      return new KeyPair(publicKey, factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  // For secret and private key bytes: the Base64 is what gets stored, and the raw bytes are wiped.
  private static String encodeAndWipe(byte[] secret) {
    try {
      return Base64.getEncoder().encodeToString(secret);
    } finally {
      Arrays.fill(secret, (byte) 0);
    }
  }

  private static String field(Map<String, String> material, String name)
      throws InvalidKeyException {
    String value = material.get(name);
    if (value == null) {
      throw new InvalidKeyException("key material has no " + name + " field");
    }
    return value;
  }

  private static byte[] decode(Map<String, String> material, String name)
      throws InvalidKeyException {
    try {
      return Base64.getDecoder().decode(field(material, name));
    } catch (IllegalArgumentException e) {
      throw new InvalidKeyException(
          "key material has a " + name + " field that is not valid Base64", e);
    }
  }
}
