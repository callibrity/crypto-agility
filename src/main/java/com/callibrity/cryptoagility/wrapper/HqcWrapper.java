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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Map;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * Post-quantum, from a different family of mathematics. ML-KEM rests on lattices; HQC rests on
 * error-correcting codes. NIST selected it in 2025 as a backup, so that a break in the lattice
 * maths does not leave everyone with nothing. That is the case for agility in one sentence: the day
 * you need this class, you want adding it to be all you have to do.
 *
 * <p>The JDK does not have HQC yet, so it comes from BouncyCastle. Compare this file with
 * MlKemWrapper: the same KEM API, a different provider behind it. The price is size. An HQC-192
 * ciphertext is about eight times the size of an ML-KEM-768 one.
 *
 * <p>Like ML-KEM, HQC comes in three strengths; the default is HQC-192, the counterpart of
 * ML-KEM-768. The HQC standard is still a draft, so the details may yet change.
 */
public final class HqcWrapper implements KeyWrapper, Inventoried {

  /**
   * The HQC parameter sets and the NIST category each targets. There is no standard OID yet, so
   * each carries the one BouncyCastle writes into its keys.
   */
  public enum ParameterSet {
    HQC_128("HQC-128", "128", 128, 1, BCObjectIdentifiers.hqc128),
    HQC_192("HQC-192", "192", 192, 3, BCObjectIdentifiers.hqc192),
    HQC_256("HQC-256", "256", 256, 5, BCObjectIdentifiers.hqc256);

    private final String algId;
    private final String size;
    private final int classicalSecurityLevel;
    private final int nistQuantumSecurityLevel;
    private final ASN1ObjectIdentifier provisionalOid;

    ParameterSet(
        String algId,
        String size,
        int classicalSecurityLevel,
        int nistQuantumSecurityLevel,
        ASN1ObjectIdentifier provisionalOid) {
      this.algId = algId;
      this.size = size;
      this.classicalSecurityLevel = classicalSecurityLevel;
      this.nistQuantumSecurityLevel = nistQuantumSecurityLevel;
      this.provisionalOid = provisionalOid;
    }

    public String algId() {
      return algId;
    }
  }

  private static final String KEM_CT = "kemCt";

  static {
    // Added last, so the JDK still serves everything it can.
    Security.addProvider(new BouncyCastlePQCProvider());
  }

  private final ParameterSet parameterSet;
  private final KeyPair kp;
  private final KEM kem;

  public HqcWrapper() throws GeneralSecurityException {
    this(ParameterSet.HQC_192, newKeyPair(ParameterSet.HQC_192));
  }

  public HqcWrapper(KeyPair kp) throws GeneralSecurityException {
    this(ParameterSet.HQC_192, kp);
  }

  public HqcWrapper(ParameterSet parameterSet, KeyPair kp) throws GeneralSecurityException {
    // The name in every envelope comes from parameterSet, so it had better match the key.
    if (!kp.getPublic().getAlgorithm().equals(parameterSet.algId)) {
      throw new InvalidKeyException(
          "an " + kp.getPublic().getAlgorithm() + " key cannot be used as " + parameterSet.algId);
    }
    this.kem = KEM.getInstance("HQC");
    this.parameterSet = parameterSet;
    this.kp = kp;
  }

  public static KeyPair newKeyPair() throws GeneralSecurityException {
    return newKeyPair(ParameterSet.HQC_192);
  }

  public static KeyPair newKeyPair(ParameterSet parameterSet) throws GeneralSecurityException {
    return KeyPairGenerator.getInstance(parameterSet.algId).generateKeyPair();
  }

  @Override
  public String algId() {
    return parameterSet.algId;
  }

  @Override
  public WrappedDek wrap(SecretKey dek, byte[] aad) throws GeneralSecurityException {
    KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate(0, 32, "AES");
    return AesGcmKeyWrap.wrap(enc.key(), dek, Map.of(KEM_CT, enc.encapsulation()), aad);
  }

  @Override
  public SecretKey unwrap(WrappedDek w, byte[] aad) throws GeneralSecurityException {
    SecretKey kek =
        kem.newDecapsulator(kp.getPrivate()).decapsulate(w.require(KEM_CT, algId()), 0, 32, "AES");
    return AesGcmKeyWrap.unwrap(kek, w, algId(), aad);
  }

  // The three parameter sets target NIST categories 1, 3 and 5, like ML-KEM's. There is no
  // standard OID yet. Until there is, BouncyCastle writes its own into every HQC key, so keys made
  // today carry an identifier that will change later.
  @Override
  public AlgorithmFacts facts() {
    return AlgorithmFacts.of(
            "kem",
            parameterSet.classicalSecurityLevel,
            parameterSet.nistQuantumSecurityLevel,
            "keygen",
            "encapsulate",
            "decapsulate")
        .withParameterSet(parameterSet.size)
        .withProvisionalOid(parameterSet.provisionalOid.getId(), "BouncyCastle");
  }

  @Override
  public String provider() {
    return Providers.names(() -> kem.newEncapsulator(kp.getPublic()).providerName());
  }
}
