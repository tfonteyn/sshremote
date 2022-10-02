package com.hardbacknutter.sshclient.ciphers;

import java.security.GeneralSecurityException;

public interface ChaChaCipher
        extends AEADCipher {

    /**
     * init cipher with seq number
     */
    void update(int packetSeqNum)
            throws GeneralSecurityException;
}
