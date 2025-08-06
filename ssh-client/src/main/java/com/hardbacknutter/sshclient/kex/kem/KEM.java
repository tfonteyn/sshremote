package com.hardbacknutter.sshclient.kex.kem;

import org.jspecify.annotations.NonNull;

/**
 * Key Encapsulation Mechanism.
 */
public interface KEM {

    void init();

    int getPublicKeyLength();

    byte @NonNull [] getPublicKey();

    int getEncapsulationLength();

    byte @NonNull [] extractSecret(byte[] encapsulation);
}
