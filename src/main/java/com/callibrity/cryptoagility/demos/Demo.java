package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Entry point: picks the demo to run from the first argument. See ./demo. */
public final class Demo {

    private static final String USAGE = """
            usage: ./demo <command>

              swap            the demo from the talk: RSA, then ML-KEM, both decrypt (in memory)
              write "text"    encrypt under the algorithm in config/crypto.properties, save to data/
              read            decrypt everything in data/, whatever wrapped it
              list            one line per stored envelope: algorithm and sizes (alias: ls)
              show [record]   draw a stored envelope, or all of them, field by field
              rewrap          move stored envelopes to the configured algorithm, data untouched
              crack [record]  break a record wrapped with the toy RSA key, using only the public key
              pitfalls        two ways an algorithm change goes wrong
            """;

    private Demo() {}

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        String command = args.length == 0 ? "" : args[0];
        try {
            switch (command) {
                case "swap" -> SwapDemo.run();
                case "write" -> {
                    if (args.length < 2) {
                        fail("write needs some text, for example: ./demo write \"hello\"");
                    }
                    StoreCommands.write(String.join(" ", Arrays.copyOfRange(args, 1, args.length)));
                }
                case "read" -> StoreCommands.read();
                case "list", "ls" -> StoreCommands.list();
                case "show" -> StoreCommands.show(args.length < 2 ? null : args[1]);
                case "rewrap" -> StoreCommands.rewrap();
                case "crack" -> CrackCommand.run(args.length < 2 ? null : args[1]);
                case "pitfalls" -> PitfallsDemo.run();
                default -> {
                    System.err.print(USAGE);
                    System.exit(2);
                }
            }
        } catch (UnknownAlgorithmException e) {
            fail(e.getMessage());
        }
    }

    static void fail(String message) {
        System.err.println("error: " + message);
        System.exit(1);
    }
}
