package com.hardbacknutter.sshclient.signature;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6">
 * RFC 8032 Edwards-Curve Digital Signature Algorithm (EdDSA), section 5.1.6. Sign</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8709#section-6">
 * RFC 8709 Ed25519 and Ed448 Public Key Algorithms, section 6 Signature format</a>
 */
public class SshSignatureEd448
        extends SshSignatureBase {

    public SshSignatureEd448() {
        super("Ed448");
    }
}
