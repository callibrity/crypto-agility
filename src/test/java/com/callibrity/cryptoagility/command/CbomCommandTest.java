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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.callibrity.cryptoagility.cbom.CycloneDx;
import com.callibrity.cryptoagility.cbom.CycloneDx.Bom;
import com.callibrity.cryptoagility.cbom.CycloneDx.Component;
import com.callibrity.cryptoagility.cbom.CycloneDx.Dependency;
import com.callibrity.cryptoagility.cbom.CycloneDx.Property;
import com.callibrity.cryptoagility.cipher.ChaCha20Poly1305;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrapper.HqcWrapper;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class CbomCommandTest {

  // The commands' output is not what these tests check, so it is thrown away.
  private static final PrintWriter OUT = new PrintWriter(Writer.nullWriter());

  @TempDir Path dataDir;

  private Workspace ws;

  @BeforeEach
  void write_records_under_two_algorithms() throws GeneralSecurityException, IOException {
    ws = new Workspace(dataDir);
    write("RSA-OAEP-3072", "customer record #1");
    write("RSA-OAEP-3072", "customer record #2");
    write("ML-KEM-768", "customer record #3");
  }

  private void write(String alg, String text) throws GeneralSecurityException, IOException {
    StoreCommands.write(OUT, ws, ws.currentKey(alg), DataCiphers.DEFAULT, text);
  }

  private Bom inventory() throws GeneralSecurityException, IOException {
    return CbomCommand.document(ws, ws.envelopes().all());
  }

  private static Component component(Bom bom, String bomRef) {
    return bom.components().stream()
        .filter(c -> bomRef.equals(c.bomRef()))
        .findFirst()
        .orElseThrow();
  }

  private static String property(Component component, String name) {
    return component.properties().stream()
        .filter(p -> p.name().equals("cryptoagility:" + name))
        .map(Property::value)
        .findFirst()
        .orElse(null);
  }

  @Nested
  class For_each_algorithm_in_use {

    @Test
    void counts_the_records_it_protects() throws GeneralSecurityException, IOException {
      Bom bom = inventory();

      assertEquals("2", property(component(bom, "crypto/algorithm/kek/RSA-OAEP-3072"), "records"));
      assertEquals(
          "record-0001,record-0002",
          property(component(bom, "crypto/algorithm/kek/RSA-OAEP-3072"), "recordIds"));
      assertEquals("1", property(component(bom, "crypto/algorithm/kek/ML-KEM-768"), "records"));
    }

    @Test
    void takes_its_quantum_security_level_from_the_wrapper()
        throws GeneralSecurityException, IOException {
      Bom bom = inventory();

      assertEquals(0, levelOf(bom, "RSA-OAEP-3072"));
      assertEquals(3, levelOf(bom, "ML-KEM-768"));
    }

    @Test
    void says_which_kind_of_key_it_is_used_with() throws GeneralSecurityException, IOException {
      Bom bom = inventory();

      assertEquals("dek", property(component(bom, "crypto/algorithm/dek/AES-256-GCM"), "keyRole"));
      assertEquals("kek", property(component(bom, "crypto/algorithm/kek/ML-KEM-768"), "keyRole"));
    }

    @Test
    void counts_every_record_against_the_data_algorithm()
        throws GeneralSecurityException, IOException {
      Bom bom = inventory();

      assertEquals("3", property(component(bom, "crypto/algorithm/dek/AES-256-GCM"), "records"));
    }

    @Test
    void leaves_out_algorithms_no_record_uses() throws GeneralSecurityException, IOException {
      Bom bom = inventory();

      assertTrue(bom.components().stream().noneMatch(c -> "HQC-192".equals(c.name())));
    }

    private int levelOf(Bom bom, String alg) {
      return component(bom, "crypto/algorithm/kek/" + alg)
          .cryptoProperties()
          .algorithmProperties()
          .nistQuantumSecurityLevel();
    }
  }

  @Nested
  class For_an_algorithm_with_no_standard_oid_yet {

    @Test
    void records_the_provisional_one_as_a_property_and_leaves_the_oid_field_empty()
        throws GeneralSecurityException, IOException {
      write("HQC-192", "customer record #4");

      Component hqc = component(inventory(), "crypto/algorithm/kek/HQC-192");

      assertNull(hqc.cryptoProperties().oid());
      assertEquals("1.3.6.1.4.1.22554.5.9.2", property(hqc, "provisionalOid"));
      assertEquals("BouncyCastle", property(hqc, "provisionalOidAssignedBy"));
    }

    @Test
    void matches_the_oid_bouncycastle_writes_into_the_key() throws GeneralSecurityException {
      var spki = SubjectPublicKeyInfo.getInstance(HqcWrapper.newKeyPair().getPublic().getEncoded());

      assertEquals(
          spki.getAlgorithm().getAlgorithm().getId(), new HqcWrapper().facts().provisionalOid());
    }
  }

  @Nested
  class For_an_algorithm_nobody_registered {

    @Test
    void lists_it_as_unknown_and_says_why() throws GeneralSecurityException, IOException {
      Path original = dataDir.resolve("envelopes").resolve("record-0001.envelope");
      Files.writeString(
          original, Files.readString(original).replace("alg=RSA-OAEP-3072", "alg=SIKE-p434"));

      Component sike = component(inventory(), "crypto/algorithm/kek/SIKE-p434");

      assertEquals("unknown", sike.cryptoProperties().algorithmProperties().primitive());
      assertNull(sike.cryptoProperties().algorithmProperties().nistQuantumSecurityLevel());
      assertEquals("nothing in this system describes this algorithm", property(sike, "status"));
    }
  }

  @Nested
  class For_the_keys {

    @Test
    void lists_each_kms_key_against_its_algorithm_with_its_state_and_use()
        throws GeneralSecurityException, IOException {
      String keyId = ws.currentKey("ML-KEM-768").keyId();

      Component key = component(inventory(), "crypto/key/" + keyId);

      var material = key.cryptoProperties().relatedCryptoMaterialProperties();
      assertEquals("crypto/algorithm/kek/ML-KEM-768", material.algorithmRef());
      assertEquals(keyId, material.id());
      assertEquals("active", material.state());
      assertEquals("kek", property(key, "keyRole"));
      assertEquals("1", property(key, "records"));
    }

    @Test
    void a_disabled_key_is_listed_as_deactivated() throws GeneralSecurityException, IOException {
      String keyId = ws.currentKey("RSA-OAEP-3072").keyId();
      ws.kms().disableKey(keyId);

      Component key = component(inventory(), "crypto/key/" + keyId);

      assertEquals("deactivated", key.cryptoProperties().relatedCryptoMaterialProperties().state());
    }

    @Test
    void every_reference_points_at_something_in_the_document()
        throws GeneralSecurityException, IOException {
      Bom bom = inventory();
      Set<String> refs = new HashSet<>();
      bom.components().forEach(c -> refs.add(c.bomRef()));
      refs.add(bom.metadata().component().bomRef());

      for (Dependency dependency : bom.dependencies()) {
        assertTrue(refs.contains(dependency.ref()), dependency.ref());
        assertTrue(refs.containsAll(dependency.dependsOn()), dependency.dependsOn().toString());
      }
      bom.components().stream()
          .filter(c -> c.cryptoProperties().relatedCryptoMaterialProperties() != null)
          .forEach(
              c ->
                  assertTrue(
                      refs.contains(
                          c.cryptoProperties().relatedCryptoMaterialProperties().algorithmRef())));
    }
  }

  @Nested
  class As_json {

    @Test
    void uses_the_cyclonedx_names_and_values() throws GeneralSecurityException, IOException {
      String json = CycloneDx.toJson(inventory());

      assertTrue(
          json.contains("\"$schema\" : \"http://cyclonedx.org/schema/bom-1.6.schema.json\""));
      assertTrue(json.contains("\"bom-ref\" : \"crypto/algorithm/kek/ML-KEM-768\""));
      assertTrue(json.contains("\"type\" : \"cryptographic-asset\""));
      assertTrue(json.contains("\"assetType\" : \"related-crypto-material\""));
      assertTrue(json.contains("\"type\" : \"key\""));
    }

    @Test
    void leaves_out_fields_that_do_not_apply() throws GeneralSecurityException, IOException {
      String json = CycloneDx.toJson(inventory());

      assertFalse(json.contains("null"));
    }

    @Test
    void is_written_into_the_data_directory_by_the_command()
        throws GeneralSecurityException, IOException {
      CbomCommand.run(OUT, ws);

      assertTrue(Files.isRegularFile(dataDir.resolve(CbomCommand.FILE_NAME)));
    }
  }

  @Nested
  class For_every_algorithm_the_kms_offers {

    @Test
    void the_provider_is_found_at_run_time() throws GeneralSecurityException {
      assertEquals("SunJCE", ws.kms().describeAlgorithm("ML-KEM-768").provider());
      assertEquals("SunJCE", ws.kms().describeAlgorithm("RSA-OAEP-3072").provider());
      assertEquals("BCPQC", ws.kms().describeAlgorithm("HQC-192").provider());
      assertEquals("SunJCE+SunEC", ws.kms().describeAlgorithm("X25519+ML-KEM-768").provider());
    }

    @Test
    void the_cbom_records_it() throws GeneralSecurityException, IOException {
      assertEquals(
          "SunJCE",
          property(component(inventory(), "crypto/algorithm/kek/ML-KEM-768"), "provider"));
    }

    @Test
    void the_algorithms_command_lists_every_algorithm_and_cipher()
        throws GeneralSecurityException, IOException {
      var listing = new StringWriter();

      AlgorithmsCommand.run(new PrintWriter(listing), ws, "ML-KEM-768", DataCiphers.DEFAULT);

      for (String alg : ws.kms().algorithms()) {
        assertTrue(listing.toString().contains(alg), alg);
      }
      assertTrue(listing.toString().contains("ChaCha20-Poly1305"));
      assertTrue(listing.toString().contains("BCPQC"));
    }

    @Test
    void it_can_be_described_for_an_inventory() throws GeneralSecurityException {
      for (String alg : ws.kms().algorithms()) {
        assertNotNull(ws.kms().describeAlgorithm(alg).facts(), alg + " has no facts");
      }
    }
  }

  @Nested
  class For_the_data_ciphers {

    @Test
    void each_one_in_use_is_counted_as_the_dek_algorithm()
        throws GeneralSecurityException, IOException {
      StoreCommands.write(
          OUT, ws, ws.currentKey("ML-KEM-768"), ChaCha20Poly1305.INSTANCE, "customer record #4");

      Bom bom = inventory();

      assertEquals("3", property(component(bom, "crypto/algorithm/dek/AES-256-GCM"), "records"));
      assertEquals(
          "1", property(component(bom, "crypto/algorithm/dek/ChaCha20-Poly1305"), "records"));
      assertEquals(
          "dek", property(component(bom, "crypto/algorithm/dek/ChaCha20-Poly1305"), "keyRole"));
    }
  }

  @Nested
  class When_nothing_is_stored {

    @Test
    void lists_nothing() throws GeneralSecurityException, IOException {
      var empty = new Workspace(dataDir.resolve("empty"));

      Bom bom = CbomCommand.document(empty, List.of());

      assertTrue(bom.components().isEmpty());
    }
  }

  @Nested
  class For_an_envelope_that_names_no_algorithm {

    @Test
    void counts_it_under_unknown() {
      var anonymous =
          new Envelope(
              null,
              "key-000001",
              "AES-256-GCM",
              new byte[12],
              new byte[34],
              WrappedDek.of("wrappedKey", new byte[384]));

      var byAlg = CbomCommand.recordsByAlgorithm(List.of(new Stored("record-0001", anonymous)));

      assertEquals(List.of("record-0001"), byAlg.get("unknown"));
    }

    @Test
    void every_component_still_has_its_own_ref_when_neither_algorithm_is_named()
        throws GeneralSecurityException, IOException {
      var nameless =
          new Envelope(
              null,
              "key-000001",
              null,
              new byte[12],
              new byte[34],
              WrappedDek.of("wrappedKey", new byte[384]));
      List<Stored> all = new ArrayList<>(ws.envelopes().all());
      all.add(new Stored("record-0004", nameless));

      Bom bom = CbomCommand.document(ws, all);

      List<String> refs = bom.components().stream().map(Component::bomRef).toList();
      assertEquals(refs.size(), Set.copyOf(refs).size(), refs.toString());
    }
  }

  @Nested
  class When_a_record_is_damaged {

    @Test
    void the_summary_gives_no_all_clear() throws GeneralSecurityException, IOException {
      var fresh = new Workspace(dataDir.resolve("damaged"));
      StoreCommands.write(
          OUT, fresh, fresh.currentKey("ML-KEM-768"), DataCiphers.DEFAULT, "customer record #1");
      Path file = fresh.dataDir().resolve("envelopes").resolve("record-0001.envelope");
      Files.writeString(file, Files.readString(file).replaceFirst("nonce=.*", "nonce=!!!"));
      var output = new StringWriter();

      CbomCommand.run(new PrintWriter(output, true), fresh);

      assertFalse(output.toString().contains("every record is wrapped"));
      assertTrue(output.toString().contains("damaged ones are unknown"));
    }
  }
}
