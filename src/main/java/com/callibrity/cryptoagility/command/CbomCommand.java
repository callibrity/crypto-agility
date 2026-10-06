package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.cbom.CycloneDx.AlgorithmProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Bom;
import com.callibrity.cryptoagility.cbom.CycloneDx.Component;
import com.callibrity.cryptoagility.cbom.CycloneDx.ComponentType;
import com.callibrity.cryptoagility.cbom.CycloneDx.CryptoProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Dependency;
import com.callibrity.cryptoagility.cbom.CycloneDx.Metadata;
import com.callibrity.cryptoagility.cbom.CycloneDx.Property;
import com.callibrity.cryptoagility.cbom.CycloneDx.RelatedCryptoMaterialProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Tools;
import com.callibrity.cryptoagility.cbom.CycloneDx;
import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import com.callibrity.cryptoagility.kms.AlgorithmInfo;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.cbom.CycloneDx.KeyType;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * A cryptographic bill of materials for the stored data: which algorithms
 * protect it, how many records depend on each, and which keys go with them.
 * Written as a CycloneDX 1.6 CBOM, so other inventory tools can read it.
 *
 * <p>It reads only what is stored in the clear, plus what the KMS will say about
 * its keys. Nothing is decrypted. That is the payoff of every envelope naming
 * its algorithms: the inventory is a query, not an investigation.
 */
public final class CbomCommand {

    static final String FILE_NAME = "cbom.json";

    private static final String PREFIX = "cryptoagility:";
    private static final String STORE_REF = "data-store";
    private static final String UNKNOWN = "unknown";

    // NIST's names for the two kinds of key in envelope encryption (SP 800-57). CycloneDX has no field for what
    // a key is for, so they are recorded as a property.
    private static final String DEK = "dek";    // data-encryption key: one per record, encrypts the data
    private static final String KEK = "kek";    // key-encryption key: held by the KMS, wraps the DEKs

    private CbomCommand() {}

    public static void run(PrintWriter out, Workspace ws) throws GeneralSecurityException, IOException {
        List<Stored> all = ws.envelopes().all();
        Path file = ws.dataDir().resolve(FILE_NAME);
        Files.createDirectories(file.getParent());
        Files.writeString(file, CycloneDx.toJson(document(ws, all)));

        out.println(Paint.bold(String.format("  %-18s %-4s %-13s %10s %8s",
                "ALGORITHM", "KEY", "QUANTUM-SAFE", "NIST LEVEL", "RECORDS")));
        for (Map.Entry<String, List<String>> entry : recordsBy(all, Envelope::enc).entrySet()) {
            printRow(out, entry.getKey(), DEK, dataFacts(entry.getKey()), entry.getValue().size());
        }
        int vulnerable = 0;
        for (Map.Entry<String, List<String>> entry : recordsByAlgorithm(all).entrySet()) {
            AlgorithmFacts facts = wrapFacts(ws, entry.getKey());
            printRow(out, entry.getKey(), KEK, facts, entry.getValue().size());
            if (facts == null || !facts.quantumSafe()) {
                vulnerable += entry.getValue().size();
            }
        }
        out.println();
        long damaged = all.stream().filter(Stored::damaged).count();
        if (damaged > 0) {
            out.println("  " + Paint.red(damaged + " damaged record(s) could not be parsed, so what protects them is unknown"));
        }
        if (all.isEmpty()) {
            out.println("  nothing stored yet, try: write hello");
        } else if (vulnerable == 0) {
            out.println("  " + Paint.green("every record is wrapped with a quantum-safe algorithm"));
        } else {
            out.println("  " + Paint.red(vulnerable + " of " + all.size()
                    + " records still depend on a key wrap that is not quantum-safe"));
        }
        out.printf("  wrote %s (CycloneDX %s)%n", file, CycloneDx.SPEC_VERSION);
    }

    /** The CBOM: one component per algorithm in use and per KMS key, and who depends on whom. */
    static Bom document(Workspace ws, List<Stored> all) throws GeneralSecurityException, IOException {
        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();
        List<String> algorithmRefs = new ArrayList<>();

        for (Map.Entry<String, List<String>> entry : recordsBy(all, Envelope::enc).entrySet()) {
            String alg = entry.getKey();
            DataCipher cipher = DataCiphers.contains(alg) ? DataCiphers.get(alg) : null;
            Component component = algorithm(alg, dataFacts(alg), DEK, entry.getValue());
            if (cipher != null) {
                component.properties().add(property("provider", cipher.provider()));
            }
            components.add(component);
            algorithmRefs.add(algorithmRef(alg));
        }

        Map<String, List<String>> recordsByKey = recordsBy(all, Envelope::kid);
        List<KeyMetadata> keys = ws.kms().listKeys();
        for (Map.Entry<String, List<String>> entry : recordsByAlgorithm(all).entrySet()) {
            String alg = entry.getKey();
            Component component = algorithm(alg, wrapFacts(ws, alg), KEK, entry.getValue());
            AlgorithmInfo info = wrapInfo(ws, alg);
            if (info != null && info.provider() != null) {
                component.properties().add(property("provider", info.provider()));
            }
            components.add(component);
            algorithmRefs.add(algorithmRef(alg));
            List<String> keyRefs = new ArrayList<>();
            for (KeyMetadata key : keys) {
                if (key.algorithm().equals(alg)) {
                    Component material = key(key, algorithmRef(alg), recordsByKey.getOrDefault(key.keyId(), List.of()));
                    components.add(material);
                    keyRefs.add(material.bomRef());
                }
            }
            dependencies.add(new Dependency(algorithmRef(alg), keyRefs));
        }
        dependencies.addFirst(new Dependency(STORE_REF, algorithmRefs));

        var store = new Component(ComponentType.DATA, STORE_REF, "crypto-agility envelope store",
                "Envelope-encrypted records under data/envelopes", null, null);
        var tool = new Component(ComponentType.APPLICATION, null, "crypto-agility", null, null, null);
        var metadata = new Metadata(Instant.now().toString(), new Tools(List.of(tool)), store);
        return Bom.of("urn:uuid:" + UUID.randomUUID(), metadata, components, dependencies);
    }

    /** Which records each key-wrap algorithm protects, in the order the algorithms first appear. */
    static Map<String, List<String>> recordsByAlgorithm(List<Stored> all) {
        return recordsBy(all, Envelope::alg);
    }

    // Groups the readable records by one of their envelope's names. A missing name counts as unknown.
    private static Map<String, List<String>> recordsBy(List<Stored> all, Function<Envelope, String> name) {
        Map<String, List<String>> records = new LinkedHashMap<>();
        for (Stored stored : all) {
            if (stored.damaged()) {
                continue;                                      // a file that cannot be parsed has no names to count
            }
            String value = name.apply(stored.envelope());
            records.computeIfAbsent(value == null ? UNKNOWN : value, any -> new ArrayList<>()).add(stored.id());
        }
        return records;
    }

    private static AlgorithmFacts dataFacts(String alg) throws UnknownAlgorithmException {
        return DataCiphers.contains(alg) ? DataCiphers.get(alg).facts() : null;
    }

    // Null when the KMS does not offer the algorithm: that is a finding in its own right.
    static AlgorithmInfo wrapInfo(Workspace ws, String alg) throws GeneralSecurityException {
        return ws.kms().algorithms().contains(alg) ? ws.kms().describeAlgorithm(alg) : null;
    }

    static AlgorithmFacts wrapFacts(Workspace ws, String alg) throws GeneralSecurityException {
        AlgorithmInfo info = wrapInfo(ws, alg);
        return info == null ? null : info.facts();
    }

    private static Component algorithm(String name, AlgorithmFacts facts, String keyRole, List<String> recordIds) {
        AlgorithmProperties properties = facts == null ? AlgorithmProperties.unknown()
                : new AlgorithmProperties(facts.primitive(), facts.parameterSetIdentifier(), facts.curve(),
                        facts.mode(), facts.padding(), facts.cryptoFunctions(), facts.classicalSecurityLevel(),
                        facts.nistQuantumSecurityLevel());

        List<Property> notes = new ArrayList<>();
        notes.add(property("keyRole", keyRole));
        notes.add(property("records", String.valueOf(recordIds.size())));
        notes.add(property("recordIds", String.join(",", recordIds)));
        if (facts == null) {
            notes.add(property("status", "nothing in this system describes this algorithm"));
        } else if (facts.provisionalOid() != null) {
            // CycloneDX has one oid field and no way to mark it provisional, so a non-standard OID goes here instead.
            notes.add(property("provisionalOid", facts.provisionalOid()));
            notes.add(property("provisionalOidAssignedBy", facts.provisionalOidSource()));
        }
        return Component.cryptographicAsset(algorithmRef(name), name,
                CryptoProperties.algorithm(properties, facts == null ? null : facts.oid()), notes);
    }

    // One KMS key. Its material stays in the KMS; the inventory records that it exists, its state, and its use.
    private static Component key(KeyMetadata key, String algorithmRef, List<String> recordIds) {
        var material = new RelatedCryptoMaterialProperties(KeyType.KEY, key.keyId(), algorithmRef,
                key.enabled() ? "active" : "deactivated", key.created().toString());
        return Component.cryptographicAsset("crypto/key/" + key.keyId(), key.keyId(),
                CryptoProperties.keyMaterial(material),
                List.of(property("keyRole", KEK), property("records", String.valueOf(recordIds.size())),
                        property("recordIds", String.join(",", recordIds))));
    }

    private static String algorithmRef(String alg) {
        return "crypto/algorithm/" + alg;
    }

    private static Property property(String name, String value) {
        return new Property(PREFIX + name, value);
    }

    private static void printRow(PrintWriter out, String alg, String keyRole, AlgorithmFacts facts, int records) {
        String safe = quantumSafeCell(facts, 13);
        String level = facts == null ? "-" : String.valueOf(facts.nistQuantumSecurityLevel());
        out.printf("  %-18s %-4s %s %10s %8d%n", alg, keyRole.toUpperCase(), safe, level, records);
    }

    /** "yes" in green, "NO" in red, or "unknown", padded for a table column. */
    static String quantumSafeCell(AlgorithmFacts facts, int width) {
        String format = "%-" + width + "s";
        return facts == null ? Paint.red(String.format(format, UNKNOWN))
                : facts.quantumSafe() ? Paint.green(String.format(format, "yes"))
                : Paint.red(String.format(format, "NO"));
    }
}
