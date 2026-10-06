package com.callibrity.cryptoagility.commands;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * The last step of a migration: stop reading the old algorithm. It lasts only
 * for this session, so nothing is lost for good, but it shows exactly what
 * retiring would strand. Inventory with cbom, move with rewrap, then retire.
 */
public final class RetireCommand {

    private RetireCommand() {}

    public static void run(PrintWriter out, Workspace ws, String algId) throws GeneralSecurityException, IOException {
        ws.registry().retire(algId);
        out.println("  " + algId + " can no longer be read in this session");
        List<String> stranded = CbomCommand.recordsByAlgorithm(ws.envelopes().all()).getOrDefault(algId, List.of());
        if (stranded.isEmpty()) {
            out.println("  " + Paint.green("no stored records depend on it, so nothing was lost"));
        } else {
            out.println("  " + Paint.red(stranded.size() + " record(s) still depend on it and are now unreadable: "
                    + String.join(", ", stranded)));
            out.println(Paint.faint("  restart the prompt to bring it back, then rewrap before you retire"));
        }
    }
}
