package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * The commands, and the one piece of state they share: which algorithm wraps
 * new data. That is the "one config line" of the talk. Change it with use and
 * everything written afterwards follows it, while everything written before
 * still reads.
 *
 * A session always starts on RSA, the algorithm we are trying to leave.
 */
final class Shell {

    static final List<String> COMMANDS = List.of(
            "use", "algorithms", "write", "read", "list", "show", "rewrap", "crack", "keys", "cbom", "swap", "pitfalls", "help", "exit");

    private static final String HELP = """
              use [algorithm]   choose the algorithm that wraps new data, or list the choices
              algorithms        every algorithm you can use, what it is, and who provides it (alias: algs)
              write <text>      encrypt the text under the current algorithm and store the envelope
              read              decrypt everything stored, whichever algorithm wrapped it
              list              one line per stored envelope: algorithm, sizes, wrap fields
              show [record]     draw a stored envelope field by field, or all of them
              rewrap            move stored envelopes to the current algorithm, data untouched
              crack [record]    break a record wrapped with the toy RSA key, using only the public key
              keys              list the key files
              cbom              inventory the algorithms protecting stored data, and write a CycloneDX CBOM
              swap              the demo from the talk: RSA, then ML-KEM, both decrypt (in memory)
              pitfalls          two ways an algorithm change goes wrong (in memory)
              help              this list
              exit              leave
            """;

    private final Workspace ws;
    private String current = RsaWrapper.ALG_ID;

    Shell(Workspace ws) {
        this.ws = ws;
    }

    /** The algorithm that wraps new data in this session. */
    String current() {
        return current;
    }

    /** Runs one line. Returns false when the line asks to leave. */
    boolean execute(String line) {
        String[] parts = line.strip().split("\\s+", 2);
        String command = parts[0];
        String argument = parts.length > 1 ? unquote(parts[1].strip()) : "";
        try {
            switch (command) {
                case "" -> { }
                case "use" -> use(argument);
                case "algorithms", "algs" -> AlgorithmsCommand.run(ws, current);
                case "write" -> StoreCommands.write(ws, currentWrapper(), required(argument, "write needs some text"));
                case "read" -> StoreCommands.read(ws);
                case "list", "ls" -> StoreCommands.list(ws);
                case "show" -> StoreCommands.show(ws, argument);
                case "rewrap" -> StoreCommands.rewrap(ws, currentWrapper());
                case "crack" -> CrackCommand.run(ws, argument);
                case "keys" -> StoreCommands.keys(ws);
                case "cbom" -> CbomCommand.run(ws);
                case "swap" -> SwapDemo.run();
                case "pitfalls" -> PitfallsDemo.run();
                case "help", "?" -> System.out.print(HELP);
                case "exit", "quit" -> {
                    return false;
                }
                default -> throw new UsageException("unknown command " + command + ", try help");
            }
        } catch (UsageException | GeneralSecurityException | IOException e) {
            System.out.println(Paint.red("  error: " + e.getMessage()));
        }
        return true;
    }

    /** The algorithms that can be chosen, for tab completion. Empty if the keys cannot be loaded. */
    List<String> algorithms() {
        try {
            return List.copyOf(ws.registry().algIds());
        } catch (GeneralSecurityException | IOException e) {
            return List.of();
        }
    }

    /** The ids of the stored records, for tab completion. */
    List<String> recordIds() {
        try {
            return ws.envelopes().all().stream().map(Stored::id).toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    private void use(String algId) throws GeneralSecurityException, IOException {
        if (algId.isEmpty()) {
            System.out.println("  current:   " + Paint.bold(current));
            System.out.println("  available: " + String.join(", ", ws.registry().algIds()));
            return;
        }
        current = ws.registry().get(algId).algId();
        System.out.println("  new data will be wrapped with " + Paint.bold(current));
    }

    private KeyWrapper currentWrapper() throws GeneralSecurityException, IOException {
        return ws.registry().get(current);
    }

    private static String required(String argument, String message) {
        if (argument.isEmpty()) {
            throw new UsageException(message);
        }
        return argument;
    }

    private static String unquote(String text) {
        boolean quoted = text.length() >= 2
                && (text.startsWith("\"") && text.endsWith("\"") || text.startsWith("'") && text.endsWith("'"));
        return quoted ? text.substring(1, text.length() - 1) : text;
    }
}
