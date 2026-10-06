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

import com.callibrity.cryptoagility.cipher.DataCipher;
import com.callibrity.cryptoagility.cipher.DataCiphers;
import com.callibrity.cryptoagility.command.AlgorithmsCommand;
import com.callibrity.cryptoagility.command.CbomCommand;
import com.callibrity.cryptoagility.command.Paint;
import com.callibrity.cryptoagility.command.RetireCommand;
import com.callibrity.cryptoagility.command.StoreCommands;
import com.callibrity.cryptoagility.command.UsageException;
import com.callibrity.cryptoagility.command.Workspace;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrapper.RsaWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * The commands, and the one piece of state they share: which algorithm wraps new data. In a real
 * system it would be one line of configuration. Change it with use and everything written
 * afterwards follows it, while everything written before still reads.
 *
 * <p>A session always starts on RSA, the algorithm we are trying to leave.
 */
final class Shell {

  static final List<String> COMMANDS =
      List.of(
          "use",
          "algorithms",
          "write",
          "read",
          "list",
          "show",
          "rewrap",
          "retire",
          "enable",
          "keys",
          "cbom",
          "help",
          "exit");

  private static final String HELP =
      """
              use [algorithm]   choose what wraps new data keys, or what encrypts new data; on its own, list both
              algorithms        everything you can use, what it is, and who provides it (alias: algs)
              write <text>      encrypt the text under a fresh data key from the KMS and store the envelope
              read              decrypt everything stored, whichever algorithms it names
              list              one line per stored envelope: algorithm, KMS key, data cipher, size
              show [record]     draw a stored envelope field by field, or all of them
              rewrap            move stored envelopes to the current key; the data is not touched
              retire <alg>      disable every KMS key for an algorithm, and see what that strands
              enable <alg>      re-enable an algorithm's keys
              keys              list the KMS's keys
              cbom              inventory the algorithms protecting stored data, and write a CycloneDX CBOM
              help              this list
              exit              leave
            """;

  private final Workspace ws;
  private final PrintWriter out;
  private String current = RsaWrapper.ALG_ID;
  private DataCipher cipher = DataCiphers.DEFAULT;

  /** Commands write to out: the terminal's writer at the prompt, standard output otherwise. */
  Shell(Workspace ws, PrintWriter out) {
    this.ws = ws;
    this.out = out;
  }

  /** The algorithm that wraps new data keys in this session. */
  String current() {
    return current;
  }

  /**
   * What the prompt shows: the wrap algorithm, plus the data cipher when it is not the usual one.
   */
  String promptLabel() {
    return cipher == DataCiphers.DEFAULT ? current : current + " + " + cipher.algId();
  }

  /** Runs one line. Returns false when the line asks to leave. */
  boolean execute(String line) {
    String[] parts = line.strip().split("\\s+", 2);
    String command = parts[0];
    String argument = parts.length > 1 ? unquote(parts[1].strip()) : "";
    try {
      switch (command) {
        case "" -> {}
        case "use" -> use(argument);
        case "algorithms", "algs" -> AlgorithmsCommand.run(out, ws, current, cipher);
        case "write" ->
            StoreCommands.write(
                out, ws, keyFor(current), cipher, required(argument, "write needs some text"));
        case "read" -> StoreCommands.read(out, ws);
        case "list", "ls" -> StoreCommands.list(out, ws);
        case "show" -> StoreCommands.show(out, ws, argument);
        case "rewrap" -> StoreCommands.rewrap(out, ws, keyFor(current));
        case "retire" ->
            retire(
                required(argument, "retire needs an algorithm, for example: retire RSA-OAEP-3072"));
        case "enable" ->
            RetireCommand.enable(out, ws, required(argument, "enable needs an algorithm"));
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
      // A bug or a bad input nobody anticipated. Report it and keep the session alive.
      out.println(Paint.red("  unexpected error: " + e));
    }
    out.flush();
    return true;
  }

  /** Everything use accepts, for tab completion: wrap algorithms first, then data ciphers. */
  List<String> algorithms() {
    List<String> names = new ArrayList<>(ws.kms().algorithms());
    DataCiphers.all().forEach(dataCipher -> names.add(dataCipher.algId()));
    return names;
  }

  /** The wrap algorithms alone, for completing retire and enable. */
  List<String> wrapAlgorithms() {
    return ws.kms().algorithms();
  }

  /** The ids of the stored records, for tab completion. */
  List<String> recordIds() {
    try {
      return ws.envelopes().all().stream().map(Stored::id).toList();
    } catch (IOException e) {
      return List.of();
    }
  }

  // The key new data keys are wrapped with. A retired algorithm stays retired: quietly minting a
  // fresh key for it would undo the retirement.
  private KeyMetadata keyFor(String algorithm) throws GeneralSecurityException, IOException {
    if (ws.retired(algorithm)) {
      throw new UsageException(
          algorithm
              + " is retired; enable "
              + algorithm
              + " to use it again, or use another algorithm");
    }
    return ws.currentKey(algorithm);
  }

  // One verb for both layers: a data cipher's name changes how data is encrypted, an algorithm's
  // name how keys are wrapped.
  private void use(String name) throws GeneralSecurityException, IOException {
    if (name.isEmpty()) {
      String key = ws.retired(current) ? "retired" : ws.currentKey(current).keyId();
      out.println("  wrapping data keys with: " + Paint.bold(current) + " (" + key + ")");
      out.println("  encrypting data with:    " + Paint.bold(cipher.algId()));
      out.println("  wrap algorithms:         " + String.join(", ", ws.kms().algorithms()));
      out.println(
          "  data ciphers:            "
              + String.join(", ", DataCiphers.all().stream().map(DataCipher::algId).toList()));
      return;
    }
    if (DataCiphers.contains(name)) {
      cipher = DataCiphers.get(name);
      out.println("  new data will be encrypted with " + Paint.bold(cipher.algId()));
      return;
    }
    if (!ws.kms().algorithms().contains(name)) {
      throw new UsageException("no algorithm or data cipher called " + name + ", try algorithms");
    }
    KeyMetadata key = keyFor(name);
    current = name;
    out.println(
        "  new data keys will be wrapped with "
            + Paint.bold(current)
            + " using KMS key "
            + key.keyId());
  }

  // You cannot stop using the algorithm you are still writing with.
  private void retire(String algorithm) throws GeneralSecurityException, IOException {
    if (algorithm.equals(current)) {
      throw new UsageException(algorithm + " is wrapping new data; use another algorithm first");
    }
    RetireCommand.retire(out, ws, algorithm);
  }

  private static String required(String argument, String message) {
    if (argument.isEmpty()) {
      throw new UsageException(message);
    }
    return argument;
  }

  private static String unquote(String text) {
    boolean quoted =
        text.length() >= 2
            && (text.startsWith("\"") && text.endsWith("\"")
                || text.startsWith("'") && text.endsWith("'"));
    return quoted ? text.substring(1, text.length() - 1) : text;
  }
}
