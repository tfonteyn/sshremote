package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import com.hardbacknutter.sshclient.keypair.SshKeyPair;

/**
 * To be replaced with a more flexible solution, perhaps Bouncy Castle library calls.
 * <p>
 * All methods to export private keys have been removed.
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class KeyPairWriter {

    private static final String NO_PUBLIC_KEY_FOUND = "No public key found";

    /**
     * Writes the public key with the specified comment to the file.
     * <p>
     * Format: "type base64publickey comment\n"
     *
     * @param filename file name
     * @param comment  comment
     */
    @SuppressWarnings({"unused", "OverlyBroadThrowsClause"})
    public void writePublicKey(@NonNull final SshKeyPair keyPair,
                               @NonNull final String filename,
                               @NonNull final String comment)
            throws IOException, GeneralSecurityException {
        //TODO: Android API 26 limitation
        // try (final PrintWriter pw = new PrintWriter(filename, StandardCharsets.UTF_8)) {
        //noinspection ImplicitDefaultCharsetUsage
        try (final PrintWriter pw = new PrintWriter(filename)) {
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
        final byte[] sshPublicKeyBlob = keyPair.getSshEncodedPublicKey();

        final byte[] base64blob = Base64.getEncoder().encode(sshPublicKeyBlob);

        out.print(keyPair.getHostKeyAlgorithm());
        out.print(' ');
        out.print(new String(base64blob, StandardCharsets.UTF_8));
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
            throws GeneralSecurityException, FileNotFoundException {
        //TODO: Android API 26 limitation
        // try (final PrintWriter pw = new PrintWriter(filename, StandardCharsets.UTF_8)) {
        //noinspection ImplicitDefaultCharsetUsage
        try (final PrintWriter pw = new PrintWriter(filename)) {
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
                                    @NonNull final String comment) {
        final byte[] sshPublicKeyBlob = keyPair.getSshEncodedPublicKey();

        final byte[] base64blob = Base64.getEncoder().encode(sshPublicKeyBlob);

        out.println("---- BEGIN SSH2 PUBLIC KEY ----");
        out.println(("Comment: \"" + comment + "\""));
        int offset = 0;
        while (offset < base64blob.length) {
            int len = 70;
            if (base64blob.length - offset < len) {
                len = base64blob.length - offset;
            }
            out.println(new String(base64blob, offset, len, StandardCharsets.UTF_8));
            offset += len;
        }
        out.println("---- END SSH2 PUBLIC KEY ----");
    }
}
