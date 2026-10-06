package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.envelope.EnvelopeCrypto;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.store.EnvelopeStore;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.decrypt;
import static com.callibrity.cryptoagility.envelope.EnvelopeCrypto.encrypt;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The commands that work on envelopes saved on disk, so an algorithm change can be
 * explored over time: write some records, change the algorithm, write more,
 * read them all, then rewrap. list, show and keys look at what is stored
 * without decrypting anything.
 */
public final class StoreCommands {

    private StoreCommands() {}

    /** Encrypts the text with the given wrapper and saves the envelope. */
    public static void write(PrintWriter out, Workspace ws, KeyWrapper wrapper, String text) throws GeneralSecurityException, IOException {
        Envelope env = encrypt(text.getBytes(UTF_8), wrapper);
        String id = ws.envelopes().add(env);
        out.println("  " + Paint.green("saved " + id) + ": " + env.summary());
    }

    /** Decrypts every stored envelope. Nothing here is told which algorithm is in use; each envelope says. */
    public static void read(PrintWriter out, Workspace ws) throws GeneralSecurityException, IOException {
        Map<String, Integer> inUse = new TreeMap<>();
        for (Stored stored : ws.envelopes().all()) {
            Envelope env = stored.envelope();
            inUse.merge(String.valueOf(env.alg()), 1, Integer::sum);
            out.printf("  %s (%s) -> %s%n", stored.id(), env.alg(), plaintextOrFailure(env, ws));
        }
        out.println(inUse.isEmpty() ? "  nothing stored yet, try: write hello" : "\n  algorithms in use: " + inUse);
    }

    /** Moves every stored envelope onto the given algorithm by re-wrapping only its data key. */
    public static void rewrap(PrintWriter out, Workspace ws, KeyWrapper target) throws GeneralSecurityException, IOException {
        int moved = 0;
        int skipped = 0;
        long dataBytes = 0;
        for (Stored stored : ws.envelopes().all()) {
            Envelope before = stored.envelope();
            if (target.algId().equals(before.alg())) {
                out.printf("  %s already %s%n", stored.id(), before.alg());
                continue;
            }
            Envelope after;
            try {
                after = EnvelopeCrypto.rewrap(before, ws.registry(), target);
            } catch (GeneralSecurityException e) {
                out.println(Paint.red(String.format("  %s SKIPPED, still %s: %s", stored.id(), before.alg(), e.getMessage())));
                skipped++;
                continue;
            }
            ws.envelopes().put(stored.id(), after);
            out.printf("  %s %s -> %s%n", stored.id(), before.alg(), Paint.green(after.alg()));
            moved++;
            dataBytes += before.ciphertext().length;
        }
        out.printf("%n  re-wrapped %d data key(s) of 32 bytes each, re-encrypted 0 of %d data bytes%n",
                moved, dataBytes);
        if (skipped > 0) {
            out.printf("  %d record(s) could not be unwrapped and were left as they were%n", skipped);
        }
    }

    /** One line per stored envelope. Reads only what is in the clear; no keys are loaded. */
    public static void list(PrintWriter out, Workspace ws) throws IOException {
        List<Stored> all = ws.envelopes().all();
        out.println(Paint.bold(String.format("  %-12s %-18s %5s %5s  %s", "ID", "ALGORITHM", "WRAP", "DATA", "WRAP FIELDS")));
        for (Stored stored : all) {
            Envelope env = stored.envelope();
            Map<String, byte[]> wrap = env.wrappedDek().fields();
            int wrapBytes = wrap.values().stream().mapToInt(value -> value.length).sum();
            out.printf("  %-12s %-18s %5d %5d  %s%n", stored.id(), env.alg() == null ? "(none)" : env.alg(),
                    wrapBytes, env.ciphertext().length, String.join(", ", wrap.keySet()));
        }
        out.printf("%n  %d envelope(s), sizes in bytes, nothing was decrypted to list them%n", all.size());
    }

    /** Draws one stored envelope, or all of them when no record is named. Nothing is decrypted. */
    public static void show(PrintWriter out, Workspace ws, String record) throws IOException {
        List<Stored> chosen = select(ws, record);
        if (chosen.isEmpty()) {
            out.println("  nothing stored yet, try: write hello");
        }
        out.print(chosen.stream()
                .map(stored -> EnvelopeView.render(stored.id(), stored.envelope()))
                .collect(Collectors.joining("\n")));
    }

    /** Lists the key files. These stand in for a KMS; in a real system you would never see them. */
    public static void keys(PrintWriter out, Workspace ws) throws IOException {
        Map<String, Map<String, String>> files = ws.keys().all();
        if (files.isEmpty()) {
            out.println("  no keys yet, they are generated the first time one is needed");
            return;
        }
        out.println(Paint.bold(String.format("  %-28s %s", "KEY FILE", "CONTENTS")));
        files.forEach((name, fields) -> out.printf("  %-28s %s%n", name, describe(fields)));
        out.println("\n  private keys sit unencrypted on disk here, which is for the demo only");
    }

    /**
     * The stored envelopes a command should work on: all of them when no record
     * is named, otherwise the one named by id ("record-0003"), by number ("3"),
     * or by the path of an envelope file that has been copied somewhere else.
     */
    public static List<Stored> select(Workspace ws, String record) throws IOException {
        if (record.isEmpty()) {
            return ws.envelopes().all();
        }
        if (Files.isRegularFile(Path.of(record))) {
            return List.of(new Stored(record, EnvelopeStore.load(Path.of(record))));
        }
        String id = record.matches("\\d+") ? String.format("record-%04d", Integer.parseInt(record)) : record;
        List<Stored> chosen = ws.envelopes().all().stream().filter(stored -> stored.id().equals(id)).toList();
        if (chosen.isEmpty()) {
            throw new UsageException("no record called " + record + ", try list to see what is stored");
        }
        return chosen;
    }

    private static String describe(Map<String, String> fields) {
        if (fields.containsKey("algorithm") && fields.containsKey("key")) {
            return String.format("%s secret key, %d bytes", fields.get("algorithm"),
                    Base64.getDecoder().decode(fields.get("key")).length);
        }
        if (!fields.containsKey("algorithm")) {
            return String.join(", ", fields.keySet());
        }
        return String.format("%s key pair, public %d bytes, private %d bytes", fields.get("algorithm"),
                Base64.getDecoder().decode(fields.get("public")).length,
                Base64.getDecoder().decode(fields.get("private")).length);
    }

    private static String plaintextOrFailure(Envelope env, Workspace ws) {
        try {
            return new String(decrypt(env, ws.registry()), UTF_8);
        } catch (GeneralSecurityException | IOException e) {
            return Paint.red("UNREADABLE: " + e.getMessage());
        }
    }
}
