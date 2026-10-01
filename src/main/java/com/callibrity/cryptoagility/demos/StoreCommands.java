package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.EnvelopeCrypto;
import com.callibrity.cryptoagility.store.EnvelopeStore;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The commands that work on envelopes saved under data/, so the swap can be
 * explored across runs: write some records, change crypto.wrap, write more,
 * read them all, then rewrap. list and show look at what is stored without
 * decrypting anything.
 */
final class StoreCommands {

    private StoreCommands() {}

    /** Encrypts the text under whatever crypto.wrap currently says and saves the envelope. */
    static void write(String text) throws GeneralSecurityException, IOException {
        Workspace ws = Workspace.open();
        printConfig(ws);
        Envelope env = encrypt(text.getBytes(UTF_8), ws.current());
        String id = ws.envelopes().add(env);
        System.out.println("  saved " + id + ": " + env.summary());
    }

    /** Decrypts every stored envelope. Nothing here asks which algorithm is configured. */
    static void read() throws GeneralSecurityException, IOException {
        Workspace ws = Workspace.open();
        printConfig(ws);
        Map<String, Integer> inUse = new TreeMap<>();
        for (Stored stored : ws.envelopes().all()) {
            Envelope env = stored.envelope();
            inUse.merge(String.valueOf(env.alg()), 1, Integer::sum);
            System.out.printf("  %s (%s) -> %s%n", stored.id(), env.alg(), plaintextOrFailure(env, ws));
        }
        System.out.println("\nAlgorithms in use: " + (inUse.isEmpty() ? "none yet, try ./demo write \"hello\"" : inUse));
    }

    /** Moves every stored envelope onto the configured algorithm by re-wrapping only its data key. */
    static void rewrap() throws GeneralSecurityException, IOException {
        Workspace ws = Workspace.open();
        printConfig(ws);
        int moved = 0;
        long dataBytes = 0;
        for (Stored stored : ws.envelopes().all()) {
            Envelope before = stored.envelope();
            if (ws.current().algId().equals(before.alg())) {
                System.out.printf("  %s already %s%n", stored.id(), before.alg());
                continue;
            }
            Envelope after = EnvelopeCrypto.rewrap(before, ws.registry(), ws.current());
            ws.envelopes().put(stored.id(), after);
            System.out.printf("  %s %s -> %s%n", stored.id(), before.alg(), after.alg());
            moved++;
            dataBytes += before.ciphertext().length;
        }
        System.out.printf("%nRe-wrapped %d data key(s) of 32 bytes each. Re-encrypted 0 of %d data bytes.%n",
                moved, dataBytes);
    }

    /** One line per stored envelope. Reads only what is in the clear; no keys are loaded. */
    static void list() throws IOException {
        List<Stored> all = Workspace.envelopeStore().all();
        System.out.printf("  %-12s %-18s %11s %7s %6s%n", "ID", "ALGORITHM", "WRAPPED KEY", "KEM CT", "DATA");
        for (Stored stored : all) {
            Envelope env = stored.envelope();
            System.out.printf("  %-12s %-18s %11d %7s %6d%n", stored.id(), env.alg() == null ? "(none)" : env.alg(),
                    env.wrappedKey().length, env.kemCt() == null ? "-" : env.kemCt().length, env.ciphertext().length);
        }
        System.out.printf("%n%d envelope(s), sizes in bytes. Nothing was decrypted to list them.%n", all.size());
    }

    /** Draws one stored envelope, or all of them when no record is named. Nothing is decrypted. */
    static void show(String record) throws IOException {
        select(record).forEach(stored -> System.out.println(EnvelopeView.render(stored.id(), stored.envelope())));
    }

    /**
     * The stored envelopes a command should work on: all of them when no record
     * is named, otherwise the one named by id ("record-0003"), by number ("3"),
     * or by the path of an envelope file that has been copied somewhere else.
     */
    static List<Stored> select(String record) throws IOException {
        if (record != null && Files.isRegularFile(Path.of(record))) {
            return List.of(new Stored(record, EnvelopeStore.load(Path.of(record))));
        }
        List<Stored> all = Workspace.envelopeStore().all();
        if (record == null) {
            if (all.isEmpty()) {
                System.out.println("Nothing stored yet, try ./demo write \"hello\"");
            }
            return all;
        }
        String id = record.matches("\\d+") ? String.format("record-%04d", Integer.parseInt(record)) : record;
        List<Stored> chosen = all.stream().filter(stored -> stored.id().equals(id)).toList();
        if (chosen.isEmpty()) {
            Demo.fail("no record called " + record + ", run ./demo list to see what is stored");
        }
        return chosen;
    }

    private static String plaintextOrFailure(Envelope env, Workspace ws) {
        try {
            return new String(decrypt(env, ws.registry()), UTF_8);
        } catch (GeneralSecurityException e) {
            return "UNREADABLE: " + e.getMessage();
        }
    }

    private static void printConfig(Workspace ws) {
        System.out.println("config: " + Workspace.CONFIG_KEY + " = " + ws.current().algId());
    }
}
