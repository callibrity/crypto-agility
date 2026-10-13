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

import com.callibrity.cryptoagility.command.Paint;
import com.callibrity.cryptoagility.command.Workspace;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Attributes;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;

/**
 * Runs the REPL from a script so the demo can be played back hands-free: the prompt sits there
 * showing the current algorithm, you press a key, and the next command types itself and runs. It
 * uses the same Shell as the live prompt, so state carries across commands exactly as if you typed
 * them, and the same Workspace, so it reads and writes the same data.
 *
 * <p>In a real terminal it reads a single keypress in raw mode, so the command types in right after
 * the prompt on the same line. In a non-interactive console (for example IntelliJ's Run window) it
 * falls back to a line read: the prompt still shows, but the command appears on the line below. Run
 * it in a real terminal for the clean effect.
 *
 * <p>Script format: one command per line. Blank lines and lines beginning with '#' are skipped, so
 * use them to explain each step. Environment knobs:
 *
 * <ul>
 *   <li>{@code DEMO_TYPING=0} turns the typing effect off, so commands appear at once.
 *   <li>{@code DEMO_CPS=28} sets the typing speed in characters per second.
 * </ul>
 */
final class ScriptedRepl {

  private ScriptedRepl() {}

  /** Plays a script on the real terminal, with the typing effect set by the environment. */
  static void run(Workspace ws, Path script) throws IOException {
    boolean typing = !"0".equals(System.getenv("DEMO_TYPING"));
    int cps = parsePositive(System.getenv("DEMO_CPS"), 28);
    try (Terminal terminal = terminal()) {
      run(ws, script, terminal, typing, cps);
    }
  }

  /** Plays a script on the given terminal. Commands and their output both go to that terminal. */
  static void run(Workspace ws, Path script, Terminal terminal, boolean typing, int cps)
      throws IOException {
    List<String> commands = commands(script);
    PrintWriter out = terminal.writer();
    var shell = new Shell(ws, out);
    boolean dumb = terminal.getType() != null && terminal.getType().startsWith("dumb");
    LineReader reader = dumb ? LineReaderBuilder.builder().terminal(terminal).build() : null;

    out.println("Scripted demo. Press a key to run each command; Ctrl-D to stop.");
    out.println();
    out.flush();

    for (String line : commands) {
      if (dumb) {
        try {
          reader.readLine(prompt(shell)); // prompt shows; press Enter to advance
        } catch (EndOfFileException | UserInterruptException e) {
          return;
        }
      } else {
        if (!awaitKey(terminal, prompt(shell))) { // prompt shows; one keypress, not echoed
          out.println();
          out.flush();
          return;
        }
      }
      typeLine(out, line, typing, cps); // the command types itself after the prompt
      boolean keepGoing = shell.execute(line);
      out.println();
      out.flush();
      if (!keepGoing) {
        return; // 'exit' ends the demo
      }
    }
  }

  private static Terminal terminal() throws IOException {
    try {
      return TerminalBuilder.builder().build(); // real terminal: live prompt + single keypress
    } catch (IOException e) {
      return TerminalBuilder.builder().dumb(true).build();
    }
  }

  // Shows the prompt and waits for one keypress without echoing it, so the
  // prompt keeps its line. Keys pressed while the last command ran are
  // discarded before the prompt shows, never after: once the prompt is on
  // screen, the next key counts. A single key can arrive as several bytes
  // (arrow keys send an escape sequence like ESC [ A), so after the first byte
  // we drain the rest; one physical keypress always advances exactly one
  // command.
  private static boolean awaitKey(Terminal terminal, String prompt) throws IOException {
    Attributes saved = terminal.enterRawMode();
    try {
      NonBlockingReader reader = terminal.reader();
      while (reader.peek(1L) >= 0) { // discard keys pressed while the last command ran,
        reader.read(); // so a stray press cannot skip the next step
      }
      PrintWriter out = terminal.writer();
      out.print(prompt); // cursor waits after the prompt
      out.flush();
      int ch = reader.read(); // first byte of the keypress
      if (ch < 0 || ch == 3 || ch == 4) {
        return false; // EOF, Ctrl-C, Ctrl-D
      }
      while (reader.peek(5L) >= 0) { // drain the rest of a multi-byte key
        reader.read();
      }
      return true;
    } finally {
      terminal.setAttributes(saved); // back to cooked mode for output
    }
  }

  // Mirrors the live prompt: the brackets always name the current algorithm.
  private static String prompt(Shell shell) {
    return "[" + Paint.bold(shell.promptLabel()) + "] > ";
  }

  private static void typeLine(PrintWriter out, String line, boolean typing, int cps) {
    if (!typing) {
      out.println(line);
      return;
    }
    long delay = Math.max(1L, 1000L / cps);
    for (int i = 0; i < line.length(); i++) {
      out.print(line.charAt(i));
      out.flush();
      sleep(delay);
    }
    out.println();
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
