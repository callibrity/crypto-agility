package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.commands.Paint;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Attributes;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs the REPL from a script so the demo can be presented hands-free: the
 * prompt sits there showing the current algorithm, you press a key, and the
 * next command types itself and runs. It uses the same Shell as the live
 * prompt, so state carries across commands exactly as if you typed them.
 *
 * In a real terminal it reads a single keypress in raw mode, so the command
 * types in right after the prompt on the same line. In a non-interactive
 * console (for example IntelliJ's Run window) it falls back to a line read:
 * the prompt still shows, but the command appears on the line below. Run it in
 * a real terminal for the clean effect.
 *
 * Script format: one command per line. Blank lines and lines beginning with '#'
 * are skipped, so use them to explain each step. Environment knobs:
 *   DEMO_TYPING=0   turn the typing effect off (commands appear at once)
 *   DEMO_CPS=28     characters per second for the typing effect
 */
final class ScriptedRepl {

    private ScriptedRepl() {}

    static void run(Shell shell, Path script) throws IOException {
        List<String> commands = commands(script);
        boolean typing = !"0".equals(System.getenv("DEMO_TYPING"));
        int cps = parsePositive(System.getenv("DEMO_CPS"), 28);

        try (Terminal terminal = terminal()) {
            boolean dumb = terminal.getType() != null && terminal.getType().startsWith("dumb");
            LineReader reader = dumb ? LineReaderBuilder.builder().terminal(terminal).build() : null;

            System.out.println("Scripted demo. Press a key to run each command; Ctrl-D to stop.");
            System.out.println();
            System.out.flush();

            for (String line : commands) {
                if (dumb) {
                    try {
                        reader.readLine(prompt(shell));      // prompt shows; press Enter to advance
                    } catch (EndOfFileException | UserInterruptException e) {
                        return;
                    }
                } else {
                    System.out.print(prompt(shell));         // prompt shows and waits, cursor after it
                    System.out.flush();
                    if (!awaitKey(terminal)) {               // one keypress, not echoed
                        System.out.println();
                        return;
                    }
                }
                typeLine(line, typing, cps);                  // the command types itself after the prompt
                boolean keepGoing = shell.execute(line);      // command output goes to System.out
                System.out.flush();
                System.out.println();
                if (!keepGoing) {
                    return;                                   // 'exit' ends the demo
                }
            }
        }
    }

    private static Terminal terminal() throws IOException {
        try {
            return TerminalBuilder.builder().build();         // real terminal: live prompt + single keypress
        } catch (IOException e) {
            return TerminalBuilder.builder().dumb(true).build();
        }
    }

    // Waits for one keypress without echoing it, so the prompt keeps its line.
    // A single key can arrive as several bytes (arrow keys send an escape
    // sequence like ESC [ A), so after the first byte we drain the rest; one
    // physical keypress always advances exactly one command.
    private static boolean awaitKey(Terminal terminal) throws IOException {
        Attributes saved = terminal.enterRawMode();
        try {
            NonBlockingReader reader = terminal.reader();
            int ch = reader.read();                           // first byte of the keypress
            if (ch < 0 || ch == 3 || ch == 4) {
                return false;                                 // EOF, Ctrl-C, Ctrl-D
            }
            while (reader.peek(5L) >= 0) {                    // drain the rest of a multi-byte key
                reader.read();
            }
            return true;
        } finally {
            terminal.setAttributes(saved);                    // back to cooked mode for output
        }
    }

    // Mirrors the live prompt: the brackets always name the current algorithm.
    private static String prompt(Shell shell) {
        return "[" + Paint.bold(shell.current()) + "] > ";
    }

    private static void typeLine(String line, boolean typing, int cps) {
        if (!typing) {
            System.out.println(line);
            return;
        }
        long delay = Math.max(1L, 1000L / cps);
        for (int i = 0; i < line.length(); i++) {
            System.out.print(line.charAt(i));
            System.out.flush();
            sleep(delay);
        }
        System.out.println();
    }

    private static List<String> commands(Path script) throws IOException {
        List<String> out = new ArrayList<>();
        for (String raw : Files.readAllLines(script, StandardCharsets.UTF_8)) {
            String line = raw.strip();
            if (!line.isEmpty() && !line.startsWith("#")) {
                out.add(line);
            }
        }
        return out;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static int parsePositive(String value, int fallback) {
        if (value == null) {
            return fallback;
        }
        try {
            int n = Integer.parseInt(value.strip());
            return n > 0 ? n : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
