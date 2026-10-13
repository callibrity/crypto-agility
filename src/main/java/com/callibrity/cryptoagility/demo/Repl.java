/*
 * Copyright © 2026 Callibrity, Inc. (contactus@callibrity.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.callibrity.cryptoagility.demo;

import com.callibrity.cryptoagility.command.Workspace;
import java.io.IOException;
import java.io.PrintWriter;
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

/**
 * The interactive prompt. All it adds to Shell is the terminal: line editing, history, tab
 * completion, and a prompt that always shows the current algorithm.
 */
final class Repl {

  private Repl() {}

  /** Runs the prompt on the real terminal. */
  static void run(Workspace ws) throws IOException {
    try (Terminal terminal = TerminalBuilder.builder().dumb(true).build()) {
      run(ws, terminal);
    }
  }

  /** Runs the prompt on the given terminal until exit or end of input. */
  static void run(Workspace ws, Terminal terminal) {
    // Commands print through the terminal's own writer, so their output and the line editor never
    // collide.
    PrintWriter out = terminal.writer();
    var shell = new Shell(ws, out);
    LineReader reader =
        LineReaderBuilder.builder()
            .terminal(terminal)
            .completer(completer(shell))
            // Text after "write" is taken as it is typed: quotes, backslashes and ! mean nothing
            // special.
            .parser(new DefaultParser().quoteChars(new char[0]).escapeChars(new char[0]))
            .option(LineReader.Option.DISABLE_EVENT_EXPANSION, true)
            .build();
    out.println(
        "Crypto agility demo. Type help for the commands, tab to complete, exit to leave.\n");
    while (true) {
      String line;
      try {
        line = reader.readLine(prompt(shell, terminal));
      } catch (UserInterruptException _) {
        continue; // Ctrl-C abandons the line
      } catch (EndOfFileException _) {
        return; // Ctrl-D leaves
      }
      if (!shell.execute(line)) {
        return;
      }
      out.println();
    }
  }

  // The prompt is the config line: it always says which algorithm wraps new data.
  private static String prompt(Shell shell, Terminal terminal) {
    return new AttributedStringBuilder()
        .append("[")
        .style(AttributedStyle.BOLD)
        .append(shell.promptLabel())
        .style(AttributedStyle.DEFAULT)
        .append("] > ")
        .toAnsi(terminal);
  }

  private static Completer completer(Shell shell) {
    return new AggregateCompleter(
        new ArgumentCompleter(new StringsCompleter(Shell.COMMANDS), NullCompleter.INSTANCE),
        new ArgumentCompleter(
            new StringsCompleter("use"),
            new StringsCompleter(shell::algorithms),
            NullCompleter.INSTANCE),
        new ArgumentCompleter(
            new StringsCompleter("retire", "enable"),
            new StringsCompleter(shell::wrapAlgorithms),
            NullCompleter.INSTANCE),
        new ArgumentCompleter(
            new StringsCompleter("show"),
            new StringsCompleter(shell::recordIds),
            NullCompleter.INSTANCE));
  }
}
