package com.callibrity.cryptoagility.demos;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.UnknownAlgorithmException;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.store.DemoKeys;
import com.callibrity.cryptoagility.store.EnvelopeStore;
import com.callibrity.cryptoagility.wrappers.HybridWrapper;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Properties;

/**
 * What the write, read and rewrap commands share: the configured algorithm,
 * every algorithm that can still be read, and the envelopes on disk.
 */
record Workspace(KeyWrapper current, WrapperRegistry registry, EnvelopeStore envelopes) {

    static final String CONFIG_KEY = "crypto.wrap";
    private static final Path CONFIG_FILE = Path.of("config", "crypto.properties");
    private static final Path DATA_DIR = Path.of("data");

    static Workspace open() throws GeneralSecurityException, IOException {
        WrapperRegistry registry = registry(new DemoKeys(DATA_DIR.resolve("keys")));
        String configured = configuredAlgorithm();
        if (configured == null) {
            throw new UnknownAlgorithmException(
                    CONFIG_KEY + " is not set in " + CONFIG_FILE + " (registered: " + registry.algIds() + ")");
        }
        return new Workspace(registry.get(configured), registry, new EnvelopeStore(DATA_DIR.resolve("envelopes")));
    }

    /**
     * Every algorithm this system can read. Supporting a new one is a new
     * KeyWrapper class plus one line here. Removing a line retires that
     * algorithm, and anything still wrapped with it becomes unreadable.
     */
    private static WrapperRegistry registry(DemoKeys keys) throws GeneralSecurityException, IOException {
        return new WrapperRegistry()
                .register(new RsaWrapper(keys.keyPair("rsa-3072", RsaWrapper::newKeyPair)))
                .register(new MlKemWrapper(keys.keyPair("ml-kem-768", MlKemWrapper::newKeyPair)))
                .register(new HybridWrapper(
                        keys.keyPair("hybrid-x25519", HybridWrapper::newX25519KeyPair),
                        keys.keyPair("hybrid-ml-kem-768", MlKemWrapper::newKeyPair)));
    }

    // -Dcrypto.wrap=... on the command line wins over the properties file.
    private static String configuredAlgorithm() throws IOException {
        var props = new Properties();
        try (Reader in = Files.newBufferedReader(CONFIG_FILE)) {
            props.load(in);
        }
        String configured = System.getProperty(CONFIG_KEY, props.getProperty(CONFIG_KEY));
        return configured == null || configured.isBlank() ? null : configured.trim();
    }
}
