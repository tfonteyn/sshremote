package com.hardbacknutter.sshclient.keypair;

/**
 * http://polarssl.org/kb/cryptography/asn1-key-structures-in-der-and-pem/
 * https://web.archive.org/web/20140819203300/https://polarssl.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 */
public enum Vendor {

    RAW,
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
