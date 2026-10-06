package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.wrapper.WrappedDek;

import javax.crypto.SecretKey;

/**
 * A fresh data key, twice over: the key itself, to encrypt with once and then
 * forget, and the same key wrapped under a KMS key, to store next to the data.
 * (AWS's GenerateDataKey returns these as Plaintext and CiphertextBlob.)
 */
public record DataKey(SecretKey key, String keyId, String algorithm, WrappedDek wrapped) {}
