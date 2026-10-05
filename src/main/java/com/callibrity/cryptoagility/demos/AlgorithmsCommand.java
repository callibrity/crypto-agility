package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.AlgorithmFacts;
import com.callibrity.cryptoagility.envelope.EnvelopeCrypto;
import com.callibrity.cryptoagility.envelope.Inventoried;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

/**
 * The menu: every registered algorithm, what kind it is, whether it survives a
 * quantum computer, which provider implements it, and how many stored records
 * use it. The facts come from each wrapper, the same ones the CBOM uses.
 */
final class AlgorithmsCommand {

    private AlgorithmsCommand() {}

    static void run(Workspace ws, String current) throws GeneralSecurityException, IOException {
        Map<String, List<String>> recordsByAlg = CbomCommand.recordsByAlgorithm(ws.envelopes().all());
        System.out.println(Paint.bold(String.format("    %-18s %-12s %-13s %5s  %-12s %7s",
                "ALGORITHM", "KIND", "QUANTUM-SAFE", "LEVEL", "PROVIDER", "RECORDS")));
        for (String alg : ws.registry().algIds()) {
            Inventoried inventoried = CbomCommand.inventoried(ws, alg);
            AlgorithmFacts facts = inventoried == null ? null : inventoried.facts();
            String marker = alg.equals(current) ? Paint.bold("*") : " ";
            String name = String.format("%-18s", alg);
            System.out.printf("  %s %s %-12s %s %5s  %-12s %7d%n",
                    marker, alg.equals(current) ? Paint.bold(name) : name,
                    facts == null ? "-" : facts.primitive(),
                    CbomCommand.quantumSafeCell(facts),
                    facts == null ? "-" : facts.nistQuantumSecurityLevel(),
                    inventoried == null ? "-" : inventoried.provider(),
                    recordsByAlg.getOrDefault(alg, List.of()).size());
        }
        System.out.println();
        System.out.println(Paint.faint("  * new data is wrapped with this one; change it with use"));
        System.out.println(Paint.faint("  LEVEL: NIST quantum security category; 0 means a quantum computer breaks it"));
        System.out.println(Paint.faint("  Sun* ship with the JDK, BC* is BouncyCastle, the toy RSA is hand-written"));
        System.out.println(Paint.faint("  the data itself is always " + EnvelopeCrypto.DATA_ALG_ID + "; these only wrap its key"));
    }
}
