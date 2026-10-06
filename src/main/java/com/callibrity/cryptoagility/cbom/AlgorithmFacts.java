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

import java.util.List;

/**
 * What a cryptographic inventory needs to know about an algorithm. The field names follow the
 * algorithm properties of a CycloneDX CBOM.
 *
 * @param primitive the kind of algorithm: "pke", "kem", "ae", "block-cipher", "combiner" and so on
 * @param classicalSecurityLevel roughly how many bits of work a classical attacker needs
 * @param nistQuantumSecurityLevel the NIST post-quantum security category, 1 to 5; 0 means a
 *     quantum computer breaks it
 * @param cryptoFunctions what the algorithm is used for here, such as "encapsulate" or "encrypt"
 * @param parameterSetIdentifier the key size or parameter set, or null
 * @param mode the block cipher mode, or null
 * @param padding the padding scheme, or null
 * @param curve the elliptic curve, or null
 * @param oid the standard object identifier, or null if there is none yet
 * @param provisionalOid an identifier assigned by someone other than a standards body while there
 *     is no standard one, or null
 * @param provisionalOidSource who assigned the provisional identifier, or null
 */
public record AlgorithmFacts(
    String primitive,
    int classicalSecurityLevel,
    int nistQuantumSecurityLevel,
    List<String> cryptoFunctions,
    String parameterSetIdentifier,
    String mode,
    String padding,
    String curve,
    String oid,
    String provisionalOid,
    String provisionalOidSource) {

  public static AlgorithmFacts of(
      String primitive,
      int classicalSecurityLevel,
      int nistQuantumSecurityLevel,
      String... cryptoFunctions) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        List.of(cryptoFunctions),
        null,
        null,
        null,
        null,
        null,
        null,
        null);
  }

  /** Whether a large quantum computer leaves this algorithm standing. */
  public boolean quantumSafe() {
    return nistQuantumSecurityLevel > 0;
  }

  public AlgorithmFacts withParameterSet(String value) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        value,
        mode,
        padding,
        curve,
        oid,
        provisionalOid,
        provisionalOidSource);
  }

  public AlgorithmFacts withMode(String value) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        parameterSetIdentifier,
        value,
        padding,
        curve,
        oid,
        provisionalOid,
        provisionalOidSource);
  }

  public AlgorithmFacts withPadding(String value) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        parameterSetIdentifier,
        mode,
        value,
        curve,
        oid,
        provisionalOid,
        provisionalOidSource);
  }

  public AlgorithmFacts withCurve(String value) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        parameterSetIdentifier,
        mode,
        padding,
        value,
        oid,
        provisionalOid,
        provisionalOidSource);
  }

  public AlgorithmFacts withOid(String value) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        parameterSetIdentifier,
        mode,
        padding,
        curve,
        value,
        provisionalOid,
        provisionalOidSource);
  }

  /**
   * Records an identifier that is not the standard one, such as a library's own OID for an
   * algorithm whose standard has not been finished yet.
   */
  public AlgorithmFacts withProvisionalOid(String value, String assignedBy) {
    return new AlgorithmFacts(
        primitive,
        classicalSecurityLevel,
        nistQuantumSecurityLevel,
        cryptoFunctions,
        parameterSetIdentifier,
        mode,
        padding,
        curve,
        oid,
        value,
        assignedBy);
  }
}
