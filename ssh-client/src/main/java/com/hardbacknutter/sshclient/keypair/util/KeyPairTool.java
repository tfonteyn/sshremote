package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.EdKeyType;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairPKCS8;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;

/**
 * Provides {@link #generateKeyPair(String, int)} to generate keys
 * and a set of methods to {@link #load} keys from files, {@code byte[]} or {@link Reader}s.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class KeyPairTool {

    private static final String INVALID_FORMAT = "Invalid format";
    private static final String UNSUPPORTED_TYPE_X = "Unsupported type: ";
    @NonNull
    private final SshClientConfig config;

    /**
     * Constructor.
     */
    public KeyPairTool(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Creates a new key pair.
     *
     * @param keyType dsa | ecdsa | ed25519 | ed448 | rsa
     * @param keySize the size of the keys, in bits. Must be suitable to the type.
     *                Ignored for ed25519 | ed448
     *
     * @return the new key pair.
     */
    @NonNull
    public SshKeyPair generateKeyPair(@NonNull final String keyType,
                                      final int keySize)
            throws GeneralSecurityException {
        switch (keyType.toLowerCase(Locale.ENGLISH)) {
            case "rsa":
                return new KeyPairRSA(config, keySize);

            case "dsa":
                return new KeyPairDSA(config, keySize);

            case "ecdsa":
                return new KeyPairECDSA(config, keySize);

            case "ed25519":
                return new KeyPairEdDSA(config, EdKeyType.Ed25519);

            case "ed448":
                return new KeyPairEdDSA(config, EdKeyType.Ed448);

            default:
                throw new InvalidKeySpecException(UNSUPPORTED_TYPE_X + keyType);
        }
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
    public SshKeyPair load(@NonNull final String privateKeyFilename)
            throws IOException, GeneralSecurityException {
        String publicKeyFilename = privateKeyFilename + ".pub";
        if (!new File(publicKeyFilename).exists()) {
            publicKeyFilename = null;
        }
        return load(privateKeyFilename, publicKeyFilename);
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
    public SshKeyPair load(@NonNull final String privateKeyFilename,
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

        return load(prvKeyReader, pubKeyReader);
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
    public SshKeyPair load(@NonNull final byte[] prvKey,
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

        return load(prvKeyReader, pubKeyReader);
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
    public SshKeyPair load(@NonNull final Reader privateKeyReader,
                           @Nullable final Reader publicKeyReader)
            throws IOException, GeneralSecurityException {

        final BufferedReader prvKeyReader = new BufferedReader(privateKeyReader);
        final BufferedReader pubKeyReader = publicKeyReader != null
                ? new BufferedReader(publicKeyReader) : null;

        // Check for PuTTY format.
        final PuttyReader puttyReader = new PuttyReader(config);
        SshKeyPair keyPair = puttyReader.parse(prvKeyReader);
        if (keyPair != null) {
            return keyPair;
        }

        try (PemReader reader = new PemReader(prvKeyReader)) {
            final PemObject pem = reader.readPemObject();
            if (pem == null) {
                throw new IOException(INVALID_FORMAT);
            }

            // https://www.rfc-editor.org/rfc/rfc7468.html#section-4
            switch (pem.getType()) {
                case "OPENSSH PRIVATE KEY": {
                    final OpenSSHv1Reader parser = new OpenSSHv1Reader(config);
                    keyPair = parser.parse(pem);
                    break;
                }
                case "RSA PRIVATE KEY":
                case "DSA PRIVATE KEY":
                case "EC PRIVATE KEY": {
                    final LegacyPEMReader parser = new LegacyPEMReader(config);
                    keyPair = parser.parse(pem);
                    break;
                }
                case "ENCRYPTED PRIVATE KEY": {
                    keyPair = new KeyPairPKCS8.Builder(config)
                            .setPrivateKey(pem.getContent(), true)
                            .build();
                    break;
                }
                case "PRIVATE KEY": {
                    final byte[] content = pem.getContent();
                    keyPair = new KeyPairPKCS8.Builder(config)
                            .setPrivateKey(content, false)
                            .build();
                    break;
                }
                default:
                    throw new InvalidKeyException(UNSUPPORTED_TYPE_X + pem.getType());
            }
        }
        if (keyPair == null) {
            throw new IOException(INVALID_FORMAT);
        }

        if (pubKeyReader != null) {
            final PublicKeyReader.PublicKeyAndComment pkc =
                    new PublicKeyReader().parse(pubKeyReader);

            // do NOT overwrite the public key if we previously decoded it
            if (keyPair.getSshPublicKeyBlob() == null) {
                keyPair.setSshPublicKeyBlob(pkc.getBlob());
            }

            keyPair.setPublicKeyComment(pkc.getComment());
        }
        return keyPair;
    }
}
