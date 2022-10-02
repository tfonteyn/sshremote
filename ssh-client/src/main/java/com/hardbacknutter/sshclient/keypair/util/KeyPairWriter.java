package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * To be replaced with a more flexible solution, perhaps Bouncy Castle library calls.
 * <p>
 * All methods to export private keys have been removed.
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class KeyPairWriter {

    /**
     * Writes the public key with the specified comment to the file.
     * <p>
     * Format: "type base64publickey comment\n"
     *
     * @param filename file name
     * @param comment  comment
     */
    @SuppressWarnings("unused")
    public void writePublicKey(@NonNull final SshKeyPair keyPair,
                               @NonNull final String filename,
                               @NonNull final String comment)
            throws IOException, GeneralSecurityException {
        try (final PrintWriter pw = new PrintWriter(filename, StandardCharsets.UTF_8)) {
            writePublicKey(keyPair, pw, comment);
        }
    }

    /**
     * Writes the public key with the specified comment to the output stream.
     * <p>
     * Format: "type base64publickey comment\n"
     *
     * @param out     output stream
     * @param comment comment
     */
    public void writePublicKey(@NonNull final SshKeyPair keyPair,
                               @NonNull final PrintWriter out,
                               @NonNull final String comment)
            throws GeneralSecurityException {
        final byte[] pub = Base64.getEncoder().encode(keyPair.getSshPublicKeyBlob());

        out.print(keyPair.getHostKeyAlgorithm());
        out.print(' ');
        out.print(new String(pub, 0, pub.length, StandardCharsets.UTF_8));
        out.print(' ');
        out.println(comment);
    }

    /**
     * Writes the public key with the specified comment to the output stream in
     * the format defined in RFC 4716.
     *
     * @param filename file name
     * @param comment  comment
     */
    @SuppressWarnings("unused")
    public void writeSECSHPublicKey(@NonNull final SshKeyPair keyPair,
                                    @NonNull final String filename,
                                    @NonNull final String comment)
            throws IOException, GeneralSecurityException {
        try (final PrintWriter pw = new PrintWriter(filename, StandardCharsets.UTF_8)) {
            writeSECSHPublicKey(keyPair, pw, comment);
        }
    }

    /**
     * Writes the public key with the specified comment to the output stream in
     * the format defined in RFC 4716.
     *
     * @param out     output stream
     * @param comment comment
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4716">
     * RFC 4716, The Secure Shell (SSH) Public Key File Format</a>
     */
    @SuppressWarnings("WeakerAccess")
    public void writeSECSHPublicKey(@NonNull final SshKeyPair keyPair,
                                    @NonNull final PrintWriter out,
                                    @NonNull final String comment)
            throws GeneralSecurityException {

        final byte[] pub = Base64.getEncoder().encode(keyPair.getSshPublicKeyBlob());

        out.println("---- BEGIN SSH2 PUBLIC KEY ----");
        out.println(("Comment: \"" + comment + "\""));
        int offset = 0;
        while (offset < pub.length) {
            int len = 70;
            if (pub.length - offset < len) {
                len = pub.length - offset;
            }
            out.println(new String(pub, offset, len, StandardCharsets.UTF_8));
            offset += len;
        }
        out.println("---- END SSH2 PUBLIC KEY ----");
    }
}
