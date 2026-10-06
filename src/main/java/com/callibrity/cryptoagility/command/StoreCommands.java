package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.store.EnvelopeStore;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The commands that work on envelopes saved on disk, so an algorithm change can
 * be explored over time: write some records, change the algorithm, write more,
 * read them all, then rewrap. list, show and keys look at what is stored
 * without decrypting anything.
 */
public final class StoreCommands {

    private static final String DAMAGED = "damaged";
    private static final DateTimeFormatter CREATED = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private StoreCommands() {}

    /** Seals the text in a new envelope under a fresh data key from the KMS, and saves it. */
    public static void write(PrintWriter out, Workspace ws, KeyMetadata key, DataCipher cipher, String text)
            throws GeneralSecurityException, IOException {
        Envelope env = Envelope.seal(text.getBytes(UTF_8), ws.kms(), key.keyId(), cipher);
        String id = ws.envelopes().add(env);
        out.println("  " + Paint.green("saved " + id) + ": " + env.summary());
    }

    /** Decrypts every stored envelope. Nothing here is told which algorithm is in use; each envelope says. */
    public static void read(PrintWriter out, Workspace ws) throws IOException {
        Map<String, Integer> inUse = new TreeMap<>();
        for (Stored stored : ws.envelopes().all()) {
            if (stored.damaged()) {
                inUse.merge(DAMAGED, 1, Integer::sum);
                out.printf("  %s (%s) -> %s%n", stored.id(), DAMAGED, Paint.red("UNREADABLE: " + stored.problem()));
                continue;
            }
            Envelope env = stored.envelope();
            inUse.merge(algOrNone(env), 1, Integer::sum);
            out.printf("  %s (%s) -> %s%n", stored.id(), algOrNone(env), plaintextOrFailure(env, ws));
        }
        out.println(inUse.isEmpty() ? "  nothing stored yet, try: write hello" : "\n  algorithms in use: " + inUse);
    }

    /**
     * Moves every stored envelope onto the given key. The KMS re-wraps each
     * data key internally, so neither the data nor the plaintext data keys
     * pass through here.
     */
    public static void rewrap(PrintWriter out, Workspace ws, KeyMetadata target) throws IOException {
        int moved = 0;
        int skipped = 0;
        long dataBytes = 0;
        for (Stored stored : ws.envelopes().all()) {
            if (stored.damaged()) {
                out.println(Paint.red(String.format("  %s SKIPPED, damaged: %s", stored.id(), stored.problem())));
                skipped++;
                continue;
            }
            Envelope before = stored.envelope();
            if (target.keyId().equals(before.kid())) {
                out.printf("  %s already %s (%s)%n", stored.id(), before.alg(), before.kid());
                continue;
            }
            Envelope after;
            try {
                after = before.rewrap(ws.kms(), target.keyId());
            } catch (GeneralSecurityException e) {
                out.println(Paint.red(String.format("  %s SKIPPED, still %s: %s", stored.id(), before.alg(), e.getMessage())));
                skipped++;
                continue;
            }
            ws.envelopes().put(stored.id(), after);
            out.printf("  %s %s (%s) -> %s%n", stored.id(), algOrNone(before), before.kid(),
                    Paint.green(after.alg() + " (" + after.kid() + ")"));
            moved++;
            dataBytes += before.ciphertext().length;
        }
        out.printf("%n  re-wrapped %d data key(s), re-encrypted 0 of %d data bytes%n", moved, dataBytes);
        if (skipped > 0) {
            out.printf("  %d record(s) could not be re-wrapped and were left as they were%n", skipped);
        }
    }

    /** One line per stored envelope. Reads only what is in the clear; the KMS is not asked anything. */
    public static void list(PrintWriter out, Workspace ws) throws IOException {
        List<Stored> all = ws.envelopes().all();
        out.println(Paint.bold(String.format("  %-12s %-18s %-10s %-17s %6s", "ID", "ALG", "KID", "ENC", "BYTES")));
        for (Stored stored : all) {
            if (stored.damaged()) {
                out.printf("  %-12s %s%n", stored.id(), Paint.red(DAMAGED + ": " + stored.problem()));
                continue;
            }
            Envelope env = stored.envelope();
            int bytes = env.nonce().length + env.ciphertext().length
                    + env.wrappedDek().fields().values().stream().mapToInt(value -> value.length).sum();
            out.printf("  %-12s %-18s %-10s %-17s %6d%n", stored.id(), algOrNone(env), orNone(env.kid()),
                    orNone(env.enc()), bytes);
        }
        out.printf("%n  %d envelope(s), nothing was decrypted to list them%n", all.size());
    }

    /** Draws one stored envelope, or all of them when no record is named. Nothing is decrypted. */
    public static void show(PrintWriter out, Workspace ws, String record) throws IOException {
        List<Stored> chosen = select(ws, record);
        if (chosen.isEmpty()) {
            out.println("  nothing stored yet, try: write hello");
        }
        out.print(chosen.stream()
                .map(stored -> stored.damaged()
                        ? Paint.red("  " + stored.id() + " is " + DAMAGED + ": " + stored.problem()) + "\n"
                        : EnvelopeView.render(stored.id(), stored.envelope()))
                .collect(Collectors.joining("\n")));
    }

    /** The KMS's keys: what it will say about them, which is never the key itself. */
    public static void keys(PrintWriter out, Workspace ws) throws IOException {
        List<KeyMetadata> keys = ws.kms().listKeys();
        if (keys.isEmpty()) {
            out.println("  no keys yet, the KMS creates one the first time an algorithm is used");
            return;
        }
        Map<String, Long> records = ws.envelopes().all().stream()
                .filter(stored -> !stored.damaged() && stored.envelope().kid() != null)
                .collect(Collectors.groupingBy(stored -> stored.envelope().kid(), Collectors.counting()));
        out.println(Paint.bold(String.format("  %-10s %-18s %-8s %-16s %7s", "KEY", "ALGORITHM", "STATE", "CREATED", "RECORDS")));
        for (KeyMetadata key : keys) {
            String state = key.enabled() ? Paint.green(String.format("%-8s", "enabled")) : Paint.red(String.format("%-8s", "disabled"));
            out.printf("  %-10s %-18s %s %-16s %7d%n", key.keyId(), key.algorithm(), state,
                    CREATED.format(key.created()), records.getOrDefault(key.keyId(), 0L));
        }
        out.println(Paint.faint("\n  the KMS never hands these keys out; LocalKms keeps them in data/kms for you to look at"));
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
        String id = record.matches("\\d{1,9}") ? String.format("record-%04d", Integer.parseInt(record)) : record;
        List<Stored> chosen = ws.envelopes().all().stream().filter(stored -> stored.id().equals(id)).toList();
        if (chosen.isEmpty()) {
            throw new UsageException("no record called " + record + ", try list to see what is stored");
        }
        return chosen;
    }

    private static String algOrNone(Envelope env) {
        return orNone(env.alg());
    }

    private static String orNone(String value) {
        return value == null ? "(none)" : value;
    }

    private static String plaintextOrFailure(Envelope env, Workspace ws) {
        try {
            return new String(env.open(ws.kms()), UTF_8);
        } catch (GeneralSecurityException | IOException e) {
            return Paint.red("UNREADABLE: " + e.getMessage());
        }
    }
}
