package com.callibrity.cryptoagility.kms;

import com.callibrity.cryptoagility.wrapper.KeyWrapper;

import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * One algorithm, as LocalKms needs to know it: how to make key material for a
 * new key, and how to turn stored key material back into the KeyWrapper that
 * does the work. Supporting a new algorithm is a KeyWrapper class plus one of
 * these, which KeyTypes makes for you.
 */
public interface KeyType {

    String algorithm();

    /** New key material, as named text fields ready to store. */
    Map<String, String> newKeyMaterial() throws GeneralSecurityException;

    KeyWrapper wrapper(Map<String, String> material) throws GeneralSecurityException;
}
