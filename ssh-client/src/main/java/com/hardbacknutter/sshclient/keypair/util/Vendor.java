package com.hardbacknutter.sshclient.keypair.util;

/**
 * Used for vendor specific parsing.
 */
public enum Vendor {

    /** Unencrypted standard PKCS#8 format. */
    PKCS8,
    /** PKCS#8 encrypted format using PKCS#5 for the key encryption. */
    PKCS5,

    /** openssh.com standard */
    OPENSSH_V1,

    /** PuTTY Version 2 PPK files. */
    PUTTY2,
    /** PuTTY Version 3 PPK files. */
    PUTTY3
}
