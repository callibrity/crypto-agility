package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.cbom.CycloneDx;
import com.callibrity.cryptoagility.cbom.CycloneDx.Bom;
import com.callibrity.cryptoagility.cbom.CycloneDx.Component;
import com.callibrity.cryptoagility.cbom.CycloneDx.Dependency;
import com.callibrity.cryptoagility.cbom.CycloneDx.Property;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.Inventoried;
import com.callibrity.cryptoagility.envelope.WrappedDek;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrappers.HqcWrapper;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class CbomCommandTest {

    // The commands' output is not what these tests check, so it is thrown away.
    private static final PrintWriter OUT = new PrintWriter(Writer.nullWriter());

    @TempDir
    Path dataDir;

    private Workspace ws;

    @BeforeEach
    void write_records_under_two_algorithms() throws GeneralSecurityException, IOException {
        ws = new Workspace(dataDir);
        write("RSA-OAEP-3072", "customer record #1");
        write("RSA-OAEP-3072", "customer record #2");
        write("ML-KEM-768", "customer record #3");
    }

    private void write(String alg, String text) throws GeneralSecurityException, IOException {
        StoreCommands.write(OUT, ws, ws.registry().get(alg), text);
    }

    private Bom inventory() throws GeneralSecurityException, IOException {
        var all = ws.envelopes().all();
        return CbomCommand.document(ws, CbomCommand.recordsByAlgorithm(all), all.size());
    }

    private static Component component(Bom bom, String bomRef) {
        return bom.components().stream().filter(c -> bomRef.equals(c.bomRef())).findFirst().orElseThrow();
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

            assertEquals("2", property(component(bom, "crypto/algorithm/RSA-OAEP-3072"), "records"));
            assertEquals("record-0001,record-0002", property(component(bom, "crypto/algorithm/RSA-OAEP-3072"), "recordIds"));
            assertEquals("1", property(component(bom, "crypto/algorithm/ML-KEM-768"), "records"));
        }

        @Test
        void takes_its_quantum_security_level_from_the_wrapper() throws GeneralSecurityException, IOException {
            Bom bom = inventory();

            assertEquals(0, levelOf(bom, "RSA-OAEP-3072"));
            assertEquals(3, levelOf(bom, "ML-KEM-768"));
        }

        @Test
        void says_which_kind_of_key_it_is_used_with() throws GeneralSecurityException, IOException {
            Bom bom = inventory();

            assertEquals("dek", property(component(bom, "crypto/algorithm/AES-256-GCM"), "keyRole"));
            assertEquals("kek", property(component(bom, "crypto/algorithm/ML-KEM-768"), "keyRole"));
        }

        @Test
        void counts_every_record_against_the_data_algorithm() throws GeneralSecurityException, IOException {
            Bom bom = inventory();

            assertEquals("3", property(component(bom, "crypto/algorithm/AES-256-GCM"), "records"));
        }

        @Test
        void leaves_out_algorithms_no_record_uses() throws GeneralSecurityException, IOException {
            Bom bom = inventory();

            assertTrue(bom.components().stream().noneMatch(c -> "HQC-192".equals(c.name())));
        }

        private int levelOf(Bom bom, String alg) {
            return component(bom, "crypto/algorithm/" + alg).cryptoProperties().algorithmProperties()
                    .nistQuantumSecurityLevel();
        }
    }

    @Nested
    class For_an_algorithm_with_no_standard_oid_yet {

        @Test
        void records_the_provisional_one_as_a_property_and_leaves_the_oid_field_empty()
                throws GeneralSecurityException, IOException {
            write("HQC-192", "customer record #4");

            Component hqc = component(inventory(), "crypto/algorithm/HQC-192");

            assertNull(hqc.cryptoProperties().oid());
            assertEquals("1.3.6.1.4.1.22554.5.9.2", property(hqc, "provisionalOid"));
            assertEquals("BouncyCastle", property(hqc, "provisionalOidAssignedBy"));
        }

        @Test
        void matches_the_oid_bouncycastle_writes_into_the_key() throws GeneralSecurityException {
            var spki = SubjectPublicKeyInfo.getInstance(HqcWrapper.newKeyPair().getPublic().getEncoded());

            assertEquals(spki.getAlgorithm().getAlgorithm().getId(), new HqcWrapper().facts().provisionalOid());
        }
    }

    @Nested
    class For_an_algorithm_nobody_registered {

        @Test
        void lists_it_as_unknown_and_says_why() throws GeneralSecurityException, IOException {
            Path original = dataDir.resolve("envelopes").resolve("record-0001.envelope");
            Files.writeString(original, Files.readString(original).replace("alg=RSA-OAEP-3072", "alg=SIKE-p434"));

            Component sike = component(inventory(), "crypto/algorithm/SIKE-p434");

            assertEquals("unknown", sike.cryptoProperties().algorithmProperties().primitive());
            assertNull(sike.cryptoProperties().algorithmProperties().nistQuantumSecurityLevel());
            assertEquals("no registered wrapper describes this algorithm", property(sike, "status"));
        }
    }

    @Nested
    class For_the_keys {

        @Test
        void lists_both_halves_of_a_key_pair_against_its_algorithm() throws GeneralSecurityException, IOException {
            Bom bom = inventory();

            Component publicKey = component(bom, "crypto/key/ml-kem-768.keypair/public-key");
            assertEquals("crypto/algorithm/ML-KEM-768",
                    publicKey.cryptoProperties().relatedCryptoMaterialProperties().algorithmRef());
            component(bom, "crypto/key/ml-kem-768.keypair/private-key");
            assertEquals("kek", property(publicKey, "keyRole"));
        }

        @Test
        void every_reference_points_at_something_in_the_document() throws GeneralSecurityException, IOException {
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
                    .forEach(c -> assertTrue(refs.contains(c.cryptoProperties().relatedCryptoMaterialProperties().algorithmRef())));
        }
    }

    @Nested
    class As_json {

        @Test
        void uses_the_cyclonedx_names_and_values() throws GeneralSecurityException, IOException {
            String json = CycloneDx.toJson(inventory());

            assertTrue(json.contains("\"$schema\" : \"http://cyclonedx.org/schema/bom-1.6.schema.json\""));
            assertTrue(json.contains("\"bom-ref\" : \"crypto/algorithm/ML-KEM-768\""));
            assertTrue(json.contains("\"type\" : \"cryptographic-asset\""));
            assertTrue(json.contains("\"assetType\" : \"related-crypto-material\""));
            assertTrue(json.contains("\"type\" : \"public-key\""));
        }

        @Test
        void leaves_out_fields_that_do_not_apply() throws GeneralSecurityException, IOException {
            String json = CycloneDx.toJson(inventory());

            assertFalse(json.contains("null"));
        }

        @Test
        void is_written_into_the_data_directory_by_the_command() throws GeneralSecurityException, IOException {
            CbomCommand.run(OUT, ws);

            assertTrue(Files.isRegularFile(dataDir.resolve(CbomCommand.FILE_NAME)));
        }
    }

    @Nested
    class For_every_registered_algorithm {

        @Test
        void the_provider_is_found_at_run_time() throws GeneralSecurityException, IOException {
            assertEquals("SunJCE", CbomCommand.inventoried(ws, "ML-KEM-768").provider());
            assertEquals("SunJCE", CbomCommand.inventoried(ws, "RSA-OAEP-3072").provider());
            assertEquals("BCPQC", CbomCommand.inventoried(ws, "HQC-192").provider());
            assertEquals("SunJCE+SunEC", CbomCommand.inventoried(ws, "X25519+ML-KEM-768").provider());
        }

        @Test
        void the_cbom_records_it() throws GeneralSecurityException, IOException {
            assertEquals("SunJCE", property(component(inventory(), "crypto/algorithm/ML-KEM-768"), "provider"));
        }

        @Test
        void the_algorithms_command_lists_them_all() throws GeneralSecurityException, IOException {
            AlgorithmsCommand.run(OUT, ws, "ML-KEM-768");
        }

        @Test
        void the_wrapper_can_describe_itself() throws GeneralSecurityException, IOException {
            for (String alg : ws.registry().algIds()) {
                assertTrue(ws.registry().get(alg) instanceof Inventoried, alg + " does not describe itself");
            }
        }

        @Test
        void its_key_files_are_known() throws GeneralSecurityException, IOException {
            for (String alg : ws.registry().algIds()) {
                assertFalse(ws.keyFiles(alg).isEmpty(), alg + " has no key files");
            }
            assertEquals(List.of("aes-256-kw.key"), ws.keyFiles("AES-256-KW"));
            assertEquals(List.of("hybrid-x25519.keypair", "hybrid-ml-kem-768.keypair"), ws.keyFiles("X25519+ML-KEM-768"));
        }
    }

    @Nested
    class When_nothing_is_stored {

        @Test
        void lists_only_the_data_algorithm() throws GeneralSecurityException, IOException {
            var empty = new Workspace(dataDir.resolve("empty"));

            Bom bom = CbomCommand.document(empty, CbomCommand.recordsByAlgorithm(List.of()), 0);

            assertEquals(List.of("AES-256-GCM"), bom.components().stream().map(Component::name).toList());
        }
    }

    @Nested
    class For_an_envelope_that_names_no_algorithm {

        @Test
        void counts_it_under_unknown() {
            var anonymous = new Envelope(null, new byte[12], new byte[34], WrappedDek.of("wrappedKey", new byte[384]));

            var byAlg = CbomCommand.recordsByAlgorithm(List.of(new Stored("record-0001", anonymous)));

            assertEquals(List.of("record-0001"), byAlg.get("unknown"));
        }
    }
}
