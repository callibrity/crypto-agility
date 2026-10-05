package com.callibrity.cryptoagility.demos;

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
import com.callibrity.cryptoagility.wrappers.ToyRsaWrapper;

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
final class Workspace {

    private static final String TOY_RSA_PUBLIC_KEY = "rsa-toy.pub";

    private final Path dataDir;
    private final EnvelopeStore envelopes;
    private final DemoKeys keys;
    private final Map<String, List<String>> keyFiles = new HashMap<>();
    private WrapperRegistry registry;

    Workspace(Path dataDir) {
        this.dataDir = dataDir;
        this.envelopes = new EnvelopeStore(dataDir.resolve("envelopes"));
        this.keys = new DemoKeys(dataDir.resolve("keys"));
    }

    Path dataDir() {
        return dataDir;
    }

    /** The stored envelopes. Looking at them needs no keys. */
    EnvelopeStore envelopes() {
        return envelopes;
    }

    DemoKeys keys() {
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
    WrapperRegistry registry() throws GeneralSecurityException, IOException {
        if (registry == null) {
            registry = new WrapperRegistry();
            register(new RsaWrapper(keys.keyPair("rsa-3072", RsaWrapper::newKeyPair)));
            register(new EcdhWrapper(keys.keyPair("ecdh-x25519", EcdhWrapper::newKeyPair)));
            register(new AesKwWrapper(AesKwWrapper.fromFields(
                    keys.fields("aes-256-kw.key", () -> AesKwWrapper.toFields(AesKwWrapper.newKey())))));
            register(new MlKemWrapper(keys.keyPair("ml-kem-768", MlKemWrapper::newKeyPair)));
            register(new HybridWrapper(
                    keys.keyPair("hybrid-x25519", HybridWrapper::newX25519KeyPair),
                    keys.keyPair("hybrid-ml-kem-768", MlKemWrapper::newKeyPair)));
            register(new HqcWrapper(keys.keyPair("hqc-192", HqcWrapper::newKeyPair)));
            register(toyRsa());
        }
        return registry;
    }

    /** The key files that belong to an algorithm, for the inventory. Empty for one that is not registered. */
    List<String> keyFiles(String algId) throws GeneralSecurityException, IOException {
        registry();
        return keyFiles.getOrDefault(algId, List.of());
    }

    // Remembers which key files the wrapper's constructor just used, so the inventory can link keys to algorithms.
    private void register(KeyWrapper wrapper) {
        registry.register(wrapper);
        keyFiles.put(wrapper.algId(), keys.takeTouched());
    }

    // The toy key is published as a separate file, so the crack command can be seen to read only the public half.
    private ToyRsaWrapper toyRsa() throws IOException {
        var toyKeys = ToyRsaWrapper.Keys.fromFields(keys.fields("rsa-toy.key", () -> ToyRsaWrapper.newKeys().toFields()));
        keys.write(TOY_RSA_PUBLIC_KEY, toyKeys.publicKey().toFields());
        return new ToyRsaWrapper(toyKeys);
    }

    /** What an attacker has: the toy public key, and nothing else from the keys directory. */
    ToyRsaWrapper.PublicKey toyRsaPublicKey() throws IOException {
        return ToyRsaWrapper.PublicKey.fromFields(keys.read(TOY_RSA_PUBLIC_KEY));
    }
}
