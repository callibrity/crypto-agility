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
import java.io.Console;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;

/**
 * Entry point. With no arguments it starts the interactive prompt. With {@code --script <file>} it
 * plays that script hands-free (press a key, and each command types itself and runs). With any
 * other arguments it runs them as a single command, for example "read" or "cbom".
 */
public final class Demo {

  private Demo() {}

  static void main(String[] args) throws IOException {
    // Colour only when a person is watching, and not if they have asked for none.
    Console console = System.console();
    Paint.enable(console != null && console.isTerminal() && System.getenv("NO_COLOR") == null);

    run(args, Path.of("data"), new PrintWriter(System.out, true));
  }

  /**
   * Does what the arguments ask, against the given data directory. A single command's output goes
   * to out; the prompt and the scripted player use the terminal.
   */
  static void run(String[] args, Path dataDir, PrintWriter out) throws IOException {
    var ws = new Workspace(dataDir);
    if (args.length >= 2 && args[0].equals("--script")) {
      ScriptedRepl.run(ws, Path.of(args[1]));
    } else if (args.length == 0) {
      Repl.run(ws);
    } else {
      new Shell(ws, out).execute(String.join(" ", args));
    }
  }
}
