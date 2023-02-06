package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.KeyPairOpenSSHv1;
import com.hardbacknutter.sshclient.keypair.KeyPairPKCS8;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Provides a set of methods to {@link #parse} keys from files, {@code byte[]} or {@link Reader}s.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class KeyPairParser {

    private static final String INVALID_FORMAT = "Invalid format";
    private static final String UNSUPPORTED_TYPE_X = "Unsupported type: ";
    @NonNull
    private final SshClientConfig config;

    /**
     * Constructor.
     */
    public KeyPairParser(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Loads a key pair from a pair of files.
     * <p>
     * If a file with the same name and suffix {@code .pub}.
     * exists, it will be parsed for the public key.
     *
     * @param privateKeyFilename the file name of the private key file.
     *
     * @return the new KeyPair.
     */
    @NonNull
    public SshKeyPair parse(@NonNull final String privateKeyFilename)
            throws IOException, GeneralSecurityException {
        String publicKeyFilename = privateKeyFilename + ".pub";
        if (!new File(publicKeyFilename).exists()) {
            publicKeyFilename = null;
        }
        return parse(privateKeyFilename, publicKeyFilename);
    }

    /**
     * Loads a key pair from a pair of files.
     * <p>
     * For some key formats, the private-key will have the public-key embedded.
     * If you know that is the case, then 'publicKeyFilename' can be set to {@code null}.
     *
     * @param privateKeyFilename the file name of the private key file.
     * @param publicKeyFilename  (optional) the file name of the public key file.
     *
     * @return the new KeyPair.
     */
    @NonNull
    public SshKeyPair parse(@NonNull final String privateKeyFilename,
                            @Nullable final String publicKeyFilename)
            throws IOException, GeneralSecurityException {

        //TODO: Android API 26 limitation
        //noinspection ImplicitDefaultCharsetUsage
        final FileReader prvKeyReader = new FileReader(privateKeyFilename);
//      final FileReader prvKeyReader = new FileReader(privateKeyFilename, StandardCharsets.UTF_8);


        final FileReader pubKeyReader;
        if (publicKeyFilename != null) {
            //TODO: Android API 26 limitation
            //noinspection ImplicitDefaultCharsetUsage
            pubKeyReader = new FileReader(publicKeyFilename);
//          pubKeyReader = new FileReader(publicKeyFilename, StandardCharsets.UTF_8);

        } else {
            pubKeyReader = null;
        }

        return parse(prvKeyReader, pubKeyReader);
    }

    /**
     * Loads a key pair from a pair of byte[].
     * <p>
     * For some key formats, the private-key will have the public-key embedded,
     * and which case 'pubKey' can be set to {@code null}.
     *
     * @param prvKey the private key blob.
     * @param pubKey (optional) the public key blob.
     *
     * @return the new KeyPair.
     */
    @NonNull
    public SshKeyPair parse(@NonNull final byte[] prvKey,
                            @Nullable final byte[] pubKey)
            throws IOException, GeneralSecurityException {

        // Check for binary format key from "ssh-add" command on the remote.
        if (SshAgentReader.isSSHAgent(prvKey, pubKey)) {
            final SshAgentReader sshAgentReader = new SshAgentReader(config);
            return sshAgentReader.parse(prvKey);
        }

        final InputStreamReader prvKeyReader = new InputStreamReader(
                new ByteArrayInputStream(prvKey), StandardCharsets.UTF_8);

        final InputStreamReader pubKeyReader = pubKey != null
                ? new InputStreamReader(new ByteArrayInputStream(pubKey),
                                        StandardCharsets.UTF_8)
                : null;

        return parse(prvKeyReader, pubKeyReader);
    }

    /**
     * Loads a key pair from a pair of {@link Reader}s.
     *
     * @return the new KeyPair.
     *
     * @throws IOException         if the input was not recognized as any supported key format.
     * @throws InvalidKeyException if the input was recognised, but the detected format
     *                             is not supported
     */
    @NonNull
    public SshKeyPair parse(@NonNull final Reader privateKeyReader,
                            @Nullable final Reader publicKeyReader)
            throws IOException, GeneralSecurityException {

        // Use a BufferedReader as we'll need to use mark/reset.
        final BufferedReader prvKeyReader = new BufferedReader(privateKeyReader);
        final BufferedReader pubKeyReader = publicKeyReader != null
                ? new BufferedReader(publicKeyReader) : null;

        // Check for PuTTY format first.
        // The PuttyReader will reset the prvKeyReader if it fails.
        final PuttyReader puttyReader = new PuttyReader(config);
        SshKeyPair keyPair = puttyReader.parse(prvKeyReader);
        if (keyPair != null) {
            return keyPair;
        }


        try (PemReader reader = new PemReader(prvKeyReader)) {
            final PemObject pem = reader.readPemObject();
            if (pem != null) {
                // https://www.rfc-editor.org/rfc/rfc7468.html#section-4
                switch (pem.getType()) {
                    case "OPENSSH PRIVATE KEY": {
                        keyPair = new KeyPairOpenSSHv1.Builder(config)
                                .setPrivateKey(pem.getContent())
                                .build();
                        break;
                    }
                    case "ENCRYPTED PRIVATE KEY": {
                        keyPair = new KeyPairPKCS8.Builder(config)
                                .setPrivateKey(pem.getContent(), true)
                                .build();
                        break;
                    }
                    case "PRIVATE KEY": {
                        keyPair = new KeyPairPKCS8.Builder(config)
                                .setPrivateKey(pem.getContent(), false)
                                .build();
                        break;
                    }

                    case "RSA PRIVATE KEY":
                    case "DSA PRIVATE KEY":
                    case "EC PRIVATE KEY": {
                        final LegacyPEMReader parser = new LegacyPEMReader(config);
                        if (pubKeyReader != null) {
                            final PublicKeyReader.PublicKeyAndComment pkc =
                                    new PublicKeyReader().parse(pubKeyReader);
                            keyPair = parser.parse(pem, pkc.getBlob(), pkc.getEncoding());
                            keyPair.setPublicKeyComment(pkc.getComment());
                        } else {
                            keyPair = parser.parse(pem, null, null);
                        }
                        break;
                    }
                    default:
                        throw new InvalidKeyException(UNSUPPORTED_TYPE_X + pem.getType());
                }
            }
        }

        if (keyPair == null) {
            throw new IOException(INVALID_FORMAT);
        }

        return keyPair;
    }
}
