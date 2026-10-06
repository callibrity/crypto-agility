package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.commands.Workspace;
import com.callibrity.cryptoagility.commands.Paint;
import java.io.Console;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;

/**
 * Entry point. With no arguments it starts the interactive prompt. With
 * "--script <file>" it plays that script hands-free (narrate, press Enter,
 * each command types itself and runs). With any other arguments it runs them
 * as a single command, for example "swap" or "read".
 */
public final class Demo {

    private Demo() {}

    public static void main(String[] args) throws IOException {
        // Colour only when a person is watching, and not if they have asked for none.
        Console console = System.console();
        Paint.enable(console != null && console.isTerminal() && System.getenv("NO_COLOR") == null);

        var ws = new Workspace(Path.of("data"));
        if (args.length >= 2 && args[0].equals("--script")) {
            ScriptedRepl.run(new Shell(ws, standardOutput()), Path.of(args[1]));
        } else if (args.length == 0) {
            Repl.run(ws);
        } else {
            new Shell(ws, standardOutput()).execute(String.join(" ", args));
        }
    }

    private static PrintWriter standardOutput() {
        return new PrintWriter(System.out, true);
    }
}
