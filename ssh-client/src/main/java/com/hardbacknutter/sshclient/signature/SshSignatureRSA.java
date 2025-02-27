package com.hardbacknutter.sshclient.signature;

import org.jspecify.annotations.NonNull;

public class SshSignatureRSA
        extends SshSignatureBase {

    public SshSignatureRSA(@NonNull final String jcaSignatureAlgorithm) {
        super(jcaSignatureAlgorithm);
    }
}
