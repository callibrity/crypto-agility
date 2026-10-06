package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.commands.AlgorithmsCommand;
import com.callibrity.cryptoagility.commands.CbomCommand;
import com.callibrity.cryptoagility.commands.Paint;
import com.callibrity.cryptoagility.commands.RetireCommand;
import com.callibrity.cryptoagility.commands.StoreCommands;
import com.callibrity.cryptoagility.commands.UsageException;
import com.callibrity.cryptoagility.commands.Workspace;
import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.io.IOException;
import java.io.PrintWriter;
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
            "use", "algorithms", "write", "read", "list", "show", "rewrap", "retire", "keys", "cbom", "help", "exit");

    private static final String HELP = """
              use [algorithm]   choose the algorithm that wraps new data, or list the choices
              algorithms        every algorithm you can use, what it is, and who provides it (alias: algs)
              write <text>      encrypt the text under the current algorithm and store the envelope
              read              decrypt everything stored, whichever algorithm wrapped it
              list              one line per stored envelope: algorithm, sizes, wrap fields
              show [record]     draw a stored envelope field by field, or all of them
              rewrap            move stored envelopes to the current algorithm, data untouched
              retire <alg>      stop reading an algorithm for this session, and see what that strands
              keys              list the key files
              cbom              inventory the algorithms protecting stored data, and write a CycloneDX CBOM
              help              this list
              exit              leave
            """;

    private final Workspace ws;
    private final PrintWriter out;
    private String current = RsaWrapper.ALG_ID;

    /** Commands write to out: the terminal's writer at the prompt, standard output otherwise. */
    Shell(Workspace ws, PrintWriter out) {
        this.ws = ws;
        this.out = out;
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
                case "algorithms", "algs" -> AlgorithmsCommand.run(out, ws, current);
                case "write" -> StoreCommands.write(out, ws, currentWrapper(), required(argument, "write needs some text"));
                case "read" -> StoreCommands.read(out, ws);
                case "list", "ls" -> StoreCommands.list(out, ws);
                case "show" -> StoreCommands.show(out, ws, argument);
                case "rewrap" -> StoreCommands.rewrap(out, ws, currentWrapper());
                case "retire" -> retire(required(argument, "retire needs an algorithm, for example: retire RSA-OAEP-3072"));
                case "keys" -> StoreCommands.keys(out, ws);
                case "cbom" -> CbomCommand.run(out, ws);
                case "help", "?" -> out.print(HELP);
                case "exit", "quit" -> {
                    out.flush();
                    return false;
                }
                default -> throw new UsageException("unknown command " + command + ", try help");
            }
        } catch (UsageException | GeneralSecurityException | IOException e) {
            out.println(Paint.red("  error: " + e.getMessage()));
        } catch (RuntimeException e) {
            // A bug or a bad input nobody anticipated. Report it and keep the session alive: this runs on stage.
            out.println(Paint.red("  unexpected error: " + e));
        }
        out.flush();
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
            out.println("  current:   " + Paint.bold(current));
            out.println("  available: " + String.join(", ", ws.registry().algIds()));
            return;
        }
        current = ws.registry().get(algId).algId();
        out.println("  new data will be wrapped with " + Paint.bold(current));
    }

    // You cannot stop reading the algorithm you are still writing with.
    private void retire(String algId) throws GeneralSecurityException, IOException {
        if (algId.equals(current)) {
            throw new UsageException(algId + " is wrapping new data; use another algorithm first");
        }
        RetireCommand.run(out, ws, algId);
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
