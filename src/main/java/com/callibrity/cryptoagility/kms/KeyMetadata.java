package com.callibrity.cryptoagility.kms;

import java.time.Instant;

/** What a KMS will tell you about one of its keys. Never the key itself. */
public record KeyMetadata(String keyId, String algorithm, Instant created, boolean enabled) {}
