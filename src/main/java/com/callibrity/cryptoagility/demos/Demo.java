package com.callibrity.cryptoagility.demos;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Entry point. With no arguments it starts the interactive prompt. With
 * arguments it runs them as a single command, for example "swap" or "read".
 */
public final class Demo {

    private Demo() {}

    public static void main(String[] args) throws IOException {
        // Colour only when a person is watching, and not if they have asked for none.
        Console console = System.console();
        Paint.enable(console != null && console.isTerminal() && System.getenv("NO_COLOR") == null);

        var shell = new Shell(new Workspace(Path.of("data")));
        if (args.length == 0) {
            Repl.run(shell);
        } else {
            shell.execute(String.join(" ", args));
        }
    }
}
