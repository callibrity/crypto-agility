package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.cbom.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.kms.AlgorithmInfo;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The menu: every algorithm you can choose with use, for wrapping data keys
 * and for encrypting data, with what kind each is, whether it survives a
 * quantum computer, what implements it, and how much stored data uses it.
 */
public final class AlgorithmsCommand {

    private static final String HEADER = "    %-18s %-12s %-7s %5s  %-12s %4s %7s";
    private static final String ROW = "  %s %s %-12s %s %5s  %-12s %4s %7d%n";

    private AlgorithmsCommand() {}

    public static void run(PrintWriter out, Workspace ws, String currentAlgorithm, DataCipher currentCipher)
            throws GeneralSecurityException, IOException {
        List<Stored> readable = ws.envelopes().all().stream().filter(stored -> !stored.damaged()).toList();
        Map<String, Long> byAlg = count(readable, Envelope::alg);
        Map<String, Long> byCipher = count(readable, Envelope::enc);
        Map<String, Long> keys = ws.kms().listKeys().stream()
                .collect(Collectors.groupingBy(KeyMetadata::algorithm, Collectors.counting()));

        out.println(Paint.bold("  Key wrapping (the KEK, held by the KMS)"));
        out.println(Paint.bold(String.format(HEADER, "ALGORITHM", "KIND", "PQ-SAFE", "LEVEL", "PROVIDER", "KEYS", "RECORDS")));
        for (String alg : ws.kms().algorithms()) {
            AlgorithmInfo info = ws.kms().describeAlgorithm(alg);
            row(out, alg, alg.equals(currentAlgorithm), info.facts(), info.provider(),
                    String.valueOf(keys.getOrDefault(alg, 0L)), byAlg.getOrDefault(alg, 0L));
        }
        out.println();
        out.println(Paint.bold("  Data encryption (the DEK, one per record)"));
        out.println(Paint.bold(String.format(HEADER, "CIPHER", "KIND", "PQ-SAFE", "LEVEL", "PROVIDER", "", "RECORDS")));
        for (DataCipher cipher : DataCiphers.all()) {
            row(out, cipher.algId(), cipher == currentCipher, cipher.facts(), cipher.provider(), "",
                    byCipher.getOrDefault(cipher.algId(), 0L));
        }
        out.println();
        out.println(Paint.faint("  * what new data uses; change either with use"));
        out.println(Paint.faint("  LEVEL: NIST quantum security category; 0 means a quantum computer breaks it"));
        out.println(Paint.faint("  Sun* providers ship with the JDK; BC* providers are BouncyCastle"));
    }

    private static void row(PrintWriter out, String name, boolean current, AlgorithmFacts facts, String provider,
                            String keys, long records) {
        String padded = String.format("%-18s", name);
        out.printf(ROW, current ? Paint.bold("*") : " ", current ? Paint.bold(padded) : padded,
                facts == null ? "-" : facts.primitive(), CbomCommand.quantumSafeCell(facts, 7),
                facts == null ? "-" : facts.nistQuantumSecurityLevel(), provider == null ? "-" : provider,
                keys, records);
    }

    private static Map<String, Long> count(List<Stored> readable, Function<Envelope, String> name) {
        return readable.stream()
                .filter(stored -> name.apply(stored.envelope()) != null)
                .collect(Collectors.groupingBy(stored -> name.apply(stored.envelope()), Collectors.counting()));
    }
}
