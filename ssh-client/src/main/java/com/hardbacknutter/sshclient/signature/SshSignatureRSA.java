package com.hardbacknutter.sshclient.signature;

import org.jspecify.annotations.NonNull;

public class SshSignatureRSA
        extends SshSignatureBase {

    /**
     * Constructor.
     *
     * @param jcaSignatureAlgorithm standard JDK digest algorithm name
     */
    public SshSignatureRSA(@NonNull final String jcaSignatureAlgorithm) {
        super(jcaSignatureAlgorithm);
    }
}
