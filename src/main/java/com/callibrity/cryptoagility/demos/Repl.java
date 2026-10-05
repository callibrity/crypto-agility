package com.callibrity.cryptoagility.demos;

import org.jline.reader.Completer;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.DefaultParser;
import org.jline.reader.impl.completer.AggregateCompleter;
import org.jline.reader.impl.completer.ArgumentCompleter;
import org.jline.reader.impl.completer.NullCompleter;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;

import java.io.IOException;

/**
 * The interactive prompt. All it adds to Shell is the terminal: line editing,
 * history, tab completion, and a prompt that always shows the current algorithm.
 */
final class Repl {

    private Repl() {}

    static void run(Shell shell) throws IOException {
        try (Terminal terminal = TerminalBuilder.builder().dumb(true).build()) {
            LineReader reader = LineReaderBuilder.builder()
                    .terminal(terminal)
                    .completer(completer(shell))
                    // Text after "write" is taken as it is typed: quotes, backslashes and ! mean nothing special.
                    .parser(new DefaultParser().quoteChars(new char[0]).escapeChars(new char[0]))
                    .option(LineReader.Option.DISABLE_EVENT_EXPANSION, true)
                    .build();
            System.out.println("Crypto agility demo. Type help for the commands, tab to complete, exit to leave.\n");
            while (true) {
                String line;
                try {
                    line = reader.readLine(prompt(shell, terminal));
                } catch (UserInterruptException e) {
                    continue;                                    // Ctrl-C abandons the line
                } catch (EndOfFileException e) {
                    return;                                      // Ctrl-D leaves
                }
                if (!shell.execute(line)) {
                    return;
                }
                System.out.println();
            }
        }
    }

    // The prompt is the config line: it always says which algorithm wraps new data.
    private static String prompt(Shell shell, Terminal terminal) {
        return new AttributedStringBuilder()
                .append("[")
                .style(AttributedStyle.BOLD)
                .append(shell.current())
                .style(AttributedStyle.DEFAULT)
                .append("] > ")
                .toAnsi(terminal);
    }

    private static Completer completer(Shell shell) {
        return new AggregateCompleter(
                new ArgumentCompleter(new StringsCompleter(Shell.COMMANDS), NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("use"), new StringsCompleter(shell::algorithms),
                        NullCompleter.INSTANCE),
                new ArgumentCompleter(new StringsCompleter("show", "crack"), new StringsCompleter(shell::recordIds),
                        NullCompleter.INSTANCE));
    }
}
