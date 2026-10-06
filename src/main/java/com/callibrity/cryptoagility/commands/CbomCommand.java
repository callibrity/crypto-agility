package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.cbom.CycloneDx;
import com.callibrity.cryptoagility.cbom.CycloneDx.AlgorithmProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Bom;
import com.callibrity.cryptoagility.cbom.CycloneDx.Component;
import com.callibrity.cryptoagility.cbom.CycloneDx.ComponentType;
import com.callibrity.cryptoagility.cbom.CycloneDx.CryptoProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Dependency;
import com.callibrity.cryptoagility.cbom.CycloneDx.KeyType;
import com.callibrity.cryptoagility.cbom.CycloneDx.Metadata;
import com.callibrity.cryptoagility.cbom.CycloneDx.Property;
import com.callibrity.cryptoagility.cbom.CycloneDx.RelatedCryptoMaterialProperties;
import com.callibrity.cryptoagility.cbom.CycloneDx.Tools;
import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.EnvelopeCrypto;
import com.callibrity.cryptoagility.envelope.Inventoried;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
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

/**
 * A cryptographic bill of materials for the stored data: which algorithms
 * protect it, how many records depend on each, and which keys go with them.
 * Written as a CycloneDX 1.6 CBOM, so other inventory tools can read it.
 *
 * It reads only what is stored in the clear. Nothing is decrypted. That is the
 * payoff of every envelope naming its algorithm: the inventory is a query, not
 * an investigation.
 */
public final class CbomCommand {

    static final String FILE_NAME = "cbom.json";

    private static final String PREFIX = "cryptoagility:";
    private static final String STORE_REF = "data-store";

    // NIST's names for the two kinds of key in envelope encryption (SP 800-57). CycloneDX has no field for what
    // a key is for, so they are recorded as a property.
    private static final String DEK = "dek";    // data-encryption key: one per record, encrypts the data
    private static final String KEK = "kek";    // key-encryption key: wraps the DEKs

    private CbomCommand() {}

    public static void run(PrintWriter out, Workspace ws) throws GeneralSecurityException, IOException {
        List<Stored> all = ws.envelopes().all();
        Map<String, List<String>> recordsByAlg = recordsByAlgorithm(all);
        Path file = ws.dataDir().resolve(FILE_NAME);
        Files.createDirectories(file.getParent());
        Files.writeString(file, CycloneDx.toJson(document(ws, recordsByAlg, all.size())));

        out.println(Paint.bold(String.format("  %-18s %-4s %-13s %10s %8s",
                "ALGORITHM", "KEY", "QUANTUM-SAFE", "NIST LEVEL", "RECORDS")));
        printRow(out, EnvelopeCrypto.DATA_ALG_ID, DEK, EnvelopeCrypto.DATA_FACTS, all.size());
        int vulnerable = 0;
        for (Map.Entry<String, List<String>> entry : recordsByAlg.entrySet()) {
            AlgorithmFacts facts = factsFor(ws, entry.getKey());
            printRow(out, entry.getKey(), KEK, facts, entry.getValue().size());
            if (facts == null || !facts.quantumSafe()) {
                vulnerable += entry.getValue().size();
            }
        }
        out.println();
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

    /** The CBOM: one component per algorithm in use and per key, and who depends on whom. */
    static Bom document(Workspace ws, Map<String, List<String>> recordsByAlg, int recordCount)
            throws GeneralSecurityException, IOException {
        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();
        List<String> algorithmRefs = new ArrayList<>();

        components.add(algorithm(EnvelopeCrypto.DATA_ALG_ID, EnvelopeCrypto.DATA_FACTS, DEK, recordCount, List.of()));
        algorithmRefs.add(algorithmRef(EnvelopeCrypto.DATA_ALG_ID));

        for (Map.Entry<String, List<String>> entry : recordsByAlg.entrySet()) {
            String alg = entry.getKey();
            Component component = algorithm(alg, factsFor(ws, alg), KEK, entry.getValue().size(), entry.getValue());
            Inventoried described = inventoried(ws, alg);
            if (described != null) {
                component.properties().add(property("provider", described.provider()));
            }
            components.add(component);
            algorithmRefs.add(algorithmRef(alg));
            List<String> keyRefs = new ArrayList<>();
            for (String keyFile : ws.keyFiles(alg)) {
                for (Component key : keyMaterial(keyFile, algorithmRef(alg))) {
                    components.add(key);
                    keyRefs.add(key.bomRef());
                }
            }
            dependencies.add(new Dependency(algorithmRef(alg), keyRefs));
        }
        dependencies.addFirst(new Dependency(STORE_REF, algorithmRefs));

        var store = new Component(ComponentType.DATA, STORE_REF, "crypto-agility-demo envelope store",
                "Envelope-encrypted records under data/envelopes", null, null);
        var tool = new Component(ComponentType.APPLICATION, null, "crypto-agility-demo", null, null, null);
        var metadata = new Metadata(Instant.now().toString(), new Tools(List.of(tool)), store);
        return Bom.of("urn:uuid:" + UUID.randomUUID(), metadata, components, dependencies);
    }

    /** Which records each key-wrap algorithm protects, in the order the algorithms first appear. */
    static Map<String, List<String>> recordsByAlgorithm(List<Stored> all) {
        Map<String, List<String>> recordsByAlg = new LinkedHashMap<>();
        for (Stored stored : all) {
            String alg = stored.envelope().alg() == null ? "unknown" : stored.envelope().alg();
            recordsByAlg.computeIfAbsent(alg, name -> new ArrayList<>()).add(stored.id());
        }
        return recordsByAlg;
    }

    // Null when no registered wrapper describes the algorithm: that is a finding in its own right.
    private static AlgorithmFacts factsFor(Workspace ws, String alg) throws GeneralSecurityException, IOException {
        Inventoried inventoried = inventoried(ws, alg);
        return inventoried == null ? null : inventoried.facts();
    }

    static Inventoried inventoried(Workspace ws, String alg) throws GeneralSecurityException, IOException {
        try {
            KeyWrapper wrapper = ws.registry().get(alg);
            return wrapper instanceof Inventoried inventoried ? inventoried : null;
        } catch (UnknownAlgorithmException e) {
            return null;
        }
    }

    private static Component algorithm(String name, AlgorithmFacts facts, String keyRole, int records,
                                       List<String> recordIds) {
        AlgorithmProperties properties = facts == null ? AlgorithmProperties.unknown()
                : new AlgorithmProperties(facts.primitive(), facts.parameterSetIdentifier(), facts.curve(),
                        facts.mode(), facts.padding(), facts.cryptoFunctions(), facts.classicalSecurityLevel(),
                        facts.nistQuantumSecurityLevel());

        List<Property> notes = new ArrayList<>();
        notes.add(property("keyRole", keyRole));
        notes.add(property("records", String.valueOf(records)));
        if (!recordIds.isEmpty()) {
            notes.add(property("recordIds", String.join(",", recordIds)));
        }
        if (facts == null) {
            notes.add(property("status", "no registered wrapper describes this algorithm"));
        } else if (facts.provisionalOid() != null) {
            // CycloneDX has one oid field and no way to mark it provisional, so a non-standard OID goes here instead.
            notes.add(property("provisionalOid", facts.provisionalOid()));
            notes.add(property("provisionalOidAssignedBy", facts.provisionalOidSource()));
        }
        return Component.cryptographicAsset(algorithmRef(name), name,
                CryptoProperties.algorithm(properties, facts == null ? null : facts.oid()), notes);
    }

    // A key-pair file holds two keys; the only other kind here holds one secret key.
    private static List<Component> keyMaterial(String keyFile, String algorithmRef) {
        if (keyFile.endsWith(".keypair")) {
            return List.of(key(keyFile, KeyType.PUBLIC_KEY, algorithmRef), key(keyFile, KeyType.PRIVATE_KEY, algorithmRef));
        }
        return List.of(key(keyFile, KeyType.SECRET_KEY, algorithmRef));
    }

    private static Component key(String keyFile, KeyType type, String algorithmRef) {
        var material = new RelatedCryptoMaterialProperties(type, algorithmRef, "active");
        return Component.cryptographicAsset("crypto/key/" + keyFile + "/" + type.json(),
                keyFile + " (" + type.json() + ")", CryptoProperties.keyMaterial(material),
                List.of(property("keyRole", KEK), property("file", "data/keys/" + keyFile)));
    }

    private static String algorithmRef(String alg) {
        return "crypto/algorithm/" + alg;
    }

    private static Property property(String name, String value) {
        return new Property(PREFIX + name, value);
    }

    private static void printRow(PrintWriter out, String alg, String keyRole, AlgorithmFacts facts, int records) {
        String safe = quantumSafeCell(facts);
        String level = facts == null ? "-" : String.valueOf(facts.nistQuantumSecurityLevel());
        out.printf("  %-18s %-4s %s %10s %8d%n", alg, keyRole.toUpperCase(), safe, level, records);
    }

    /** "yes" in green, "NO" in red, or "unknown", padded for a table column. */
    static String quantumSafeCell(AlgorithmFacts facts) {
        return facts == null ? Paint.red(String.format("%-13s", "unknown"))
                : facts.quantumSafe() ? Paint.green(String.format("%-13s", "yes"))
                : Paint.red(String.format("%-13s", "NO"));
    }
}
