package com.hardbacknutter.sshclient.keypair;

public enum PublicKeyEncoding {

    /** OpenSSH standard format. Also used by Putty. */
    OPENSSH_V1,
    /** From a pem file. */
    X509
}
