package com.hardbacknutter.sshclient.keypair;

/**
 * Used for vendor specific parsing.
 */
public enum Vendor {

    /** PKCS#8 format. */
    PKCS8,


    ASN1,

    /** openssh.com standard */
    OPENSSH_V1,

    /** PuTTY Version 2 PPK files. */
    PUTTY2,
    /** PuTTY Version 3 PPK files. */
    PUTTY3
}
