package com.hardbacknutter.sshclient.signature;

import androidx.annotation.NonNull;

public class SshSignatureRSA
        extends SshSignatureBase {

    public SshSignatureRSA(@NonNull final String jcaSignatureAlgorithm) {
        super(jcaSignatureAlgorithm);
    }
}
