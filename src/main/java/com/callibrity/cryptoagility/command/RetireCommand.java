package com.callibrity.cryptoagility.command;

import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The last step of a migration: stop using the old algorithm, by disabling
 * every KMS key for it. A disabled key still exists, so enable brings it back,
 * which makes it safe to see exactly what retiring would strand. Inventory with
 * cbom, move with rewrap, then retire.
 */
public final class RetireCommand {

    private RetireCommand() {}

    public static void retire(PrintWriter out, Workspace ws, String algorithm) throws GeneralSecurityException, IOException {
        List<KeyMetadata> keys = keysFor(ws, algorithm, true);
        for (KeyMetadata key : keys) {
            ws.kms().disableKey(key.keyId());
        }
        out.println("  disabled " + keys.size() + " " + algorithm + " key(s) in the KMS");
        Set<String> disabled = keys.stream().map(KeyMetadata::keyId).collect(Collectors.toSet());
        List<String> stranded = ws.envelopes().all().stream()
                .filter(stored -> !stored.damaged() && disabled.contains(stored.envelope().kid()))
                .map(Stored::id)
                .toList();
        if (stranded.isEmpty()) {
            out.println("  " + Paint.green("no stored records depend on them, so nothing was lost"));
        } else {
            out.println("  " + Paint.red(stranded.size() + " record(s) still depend on them and are now unreadable: "
                    + String.join(", ", stranded)));
            out.println(Paint.faint("  enable " + algorithm + " to bring them back, then rewrap before you retire"));
        }
    }

    public static void enable(PrintWriter out, Workspace ws, String algorithm) throws GeneralSecurityException, IOException {
        List<KeyMetadata> keys = keysFor(ws, algorithm, false);
        for (KeyMetadata key : keys) {
            ws.kms().enableKey(key.keyId());
        }
        out.println("  enabled " + keys.size() + " " + algorithm + " key(s) in the KMS");
    }

    private static List<KeyMetadata> keysFor(Workspace ws, String algorithm, boolean enabled)
            throws GeneralSecurityException, IOException {
        if (!ws.kms().algorithms().contains(algorithm)) {
            throw new UsageException("the KMS has no algorithm " + algorithm);
        }
        return ws.kms().listKeys().stream()
                .filter(key -> key.algorithm().equals(algorithm) && key.enabled() == enabled)
                .toList();
    }
}
