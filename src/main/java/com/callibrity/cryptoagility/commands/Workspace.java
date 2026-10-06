package com.callibrity.cryptoagility.commands;

import com.callibrity.cryptoagility.envelope.KeyWrapper;
import com.callibrity.cryptoagility.envelope.WrapperRegistry;
import com.callibrity.cryptoagility.store.DemoKeys;
import com.callibrity.cryptoagility.store.EnvelopeStore;
import com.callibrity.cryptoagility.wrappers.AesKwWrapper;
import com.callibrity.cryptoagility.wrappers.EcdhWrapper;
import com.callibrity.cryptoagility.wrappers.HqcWrapper;
import com.callibrity.cryptoagility.wrappers.HybridWrapper;
import com.callibrity.cryptoagility.wrappers.MlKemWrapper;
import com.callibrity.cryptoagility.wrappers.RsaWrapper;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * What the commands share: the envelopes on disk, the keys on disk, and every
 * algorithm that can still be read. Everything lives under one data directory.
 */
public final class Workspace {

    private final Path dataDir;
    private final EnvelopeStore envelopes;
    private final DemoKeys keys;
    private final Map<String, List<String>> keyFiles = new HashMap<>();
    private WrapperRegistry registry;
    private WrapperRegistry building;

    public Workspace(Path dataDir) {
        this.dataDir = dataDir;
        this.envelopes = new EnvelopeStore(dataDir.resolve("envelopes"));
        this.keys = new DemoKeys(dataDir.resolve("keys"));
    }

    public Path dataDir() {
        return dataDir;
    }

    /** The stored envelopes. Looking at them needs no keys. */
    public EnvelopeStore envelopes() {
        return envelopes;
    }

    public DemoKeys keys() {
        return keys;
    }

    /**
     * Every algorithm this system can read. Supporting a new one is a new
     * KeyWrapper class plus one register line here. Removing a line retires that
     * algorithm, and anything still wrapped with it becomes unreadable.
     *
     * The keys are loaded the first time this is called, and generated if they
     * do not exist yet.
     */
    public WrapperRegistry registry() throws GeneralSecurityException, IOException {
        if (registry == null) {
            building = new WrapperRegistry();
            keyFiles.clear();
            keys.takeTouched();                                  // forget anything an earlier failed attempt touched
            register(new RsaWrapper(keys.keyPair("rsa-3072", RsaWrapper::newKeyPair)));
            register(new EcdhWrapper(keys.keyPair("ecdh-x25519", EcdhWrapper::newKeyPair)));
            register(new AesKwWrapper(AesKwWrapper.fromFields(
                    keys.fields("aes-256-kw.key", () -> AesKwWrapper.toFields(AesKwWrapper.newKey())))));
            for (MlKemWrapper.ParameterSet set : MlKemWrapper.ParameterSet.values()) {
                register(new MlKemWrapper(set, keys.keyPair(set.algId().toLowerCase(), () -> MlKemWrapper.newKeyPair(set))));
            }
            register(new HybridWrapper(
                    keys.keyPair("hybrid-x25519", HybridWrapper::newX25519KeyPair),
                    keys.keyPair("hybrid-ml-kem-768", MlKemWrapper::newKeyPair)));
            for (HqcWrapper.ParameterSet set : HqcWrapper.ParameterSet.values()) {
                register(new HqcWrapper(set, keys.keyPair(set.algId().toLowerCase(), () -> HqcWrapper.newKeyPair(set))));
            }
            registry = building;                                 // handed out only once every algorithm has loaded
        }
        return registry;
    }

    /** The key files that belong to an algorithm, for the inventory. Empty for one that is not registered. */
    public List<String> keyFiles(String algId) throws GeneralSecurityException, IOException {
        registry();
        return keyFiles.getOrDefault(algId, List.of());
    }

    // Remembers which key files the wrapper's constructor just used, so the inventory can link keys to algorithms.
    private void register(KeyWrapper wrapper) {
        building.register(wrapper);
        keyFiles.put(wrapper.algId(), keys.takeTouched());
    }
}
