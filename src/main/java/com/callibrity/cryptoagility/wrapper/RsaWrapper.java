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

import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import com.callibrity.cryptoagility.cbom.Inventoried;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/** Classical, quantum-vulnerable: RSA-OAEP wraps the data key directly. */
public final class RsaWrapper implements KeyWrapper, Inventoried {

  public static final String ALG_ID = "RSA-OAEP-3072";

  private static final String WRAPPED_KEY = "wrappedKey";
  private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";

  private final KeyPair kp;

  public RsaWrapper() throws GeneralSecurityException {
    this(newKeyPair());
  }

  public RsaWrapper(KeyPair kp) {
    this.kp = kp;
  }

  public static KeyPair newKeyPair() throws GeneralSecurityException {
    var g = KeyPairGenerator.getInstance("RSA");
    g.initialize(3072);
    return g.generateKeyPair();
  }

  @Override
  public String algId() {
    return ALG_ID;
  }

  @Override
  public WrappedDek wrap(SecretKey dek, byte[] aad) throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.WRAP_MODE, kp.getPublic(), oaep(aad));
    return WrappedDek.of(WRAPPED_KEY, c.wrap(dek));
  }

  @Override
  public SecretKey unwrap(WrappedDek w, byte[] aad) throws GeneralSecurityException {
    var c = Cipher.getInstance(TRANSFORMATION);
    c.init(Cipher.UNWRAP_MODE, kp.getPrivate(), oaep(aad));
    return (SecretKey) c.unwrap(w.require(WRAPPED_KEY, ALG_ID), "AES", Cipher.SECRET_KEY);
  }

  // Spelled out, because the JDK's "OAEPWithSHA-256AndMGF1Padding" quietly uses SHA-1 inside
  // MGF1, and other libraries read that name as SHA-256 throughout. An algorithm name that means
  // different things to different readers is its own agility problem. OAEP's label is its
  // associated data: unwrapping with a different label fails.
  private static OAEPParameterSpec oaep(byte[] aad) {
    return new OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        new PSource.PSpecified(Objects.requireNonNull(aad, "aad")));
  }

  // Classical security of RSA-3072 is about 128 bits. A quantum computer running Shor's algorithm
  // breaks it outright.
  @Override
  public AlgorithmFacts facts() {
    return AlgorithmFacts.of("pke", 128, 0, "keygen", "encrypt", "decrypt")
        .withParameterSet("3072")
        .withPadding("oaep")
        .withOid("1.2.840.113549.1.1.7");
  }

  @Override
  public String provider() {
    return Providers.names(() -> Cipher.getInstance(TRANSFORMATION).getProvider().getName());
  }
}
