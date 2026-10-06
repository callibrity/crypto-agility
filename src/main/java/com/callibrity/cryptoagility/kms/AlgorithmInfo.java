package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.cbom.AlgorithmFacts;

/** What a KMS says about an algorithm it offers: the facts for an inventory, and what implements it. */
public record AlgorithmInfo(String algorithm, AlgorithmFacts facts, String provider) {}
