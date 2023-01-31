package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.EdKeyType;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairPKCS8;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.Vendor;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPKCS5;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

public class KeyPairTool {

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
                throw new InvalidKeySpecException("Unsupported type: " + keyType);
        }
    }

    /**
     * Loads a key pair from a pair of files.
     * <p>
     * For some key formats, the private-key will have the public-key embedded,
     * and which case 'publicKeyFilename' can be set to {@code null}.
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
     */
    @SuppressWarnings("WeakerAccess")
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
                throw new InvalidKeyException("Invalid private key");
            }

            // https://www.rfc-editor.org/rfc/rfc7468.html#section-4
            switch (pem.getType()) {
                case "OPENSSH PRIVATE KEY": {
                    // current openssh v1 default
                    final OpenSSHv1Reader parser = new OpenSSHv1Reader(config);
                    keyPair = parser.parse(pem.getContent());
                    if (keyPair != null) {
                        // The public key was embedded in the privateKeyBlob
                        // but check for a 'comment' ...
                        if (pubKeyReader != null) {
                            readPublicKey(pubKeyReader, keyPair, false);
                        }
                        return keyPair;
                    } else {
                        throw new InvalidKeyException("Invalid OpenSSHv1 format");
                    }
                }
                case "RSA PRIVATE KEY": {
                    keyPair = new KeyPairRSA.Builder(config)
                            .setPrivateKey(pem.getContent())
                            .setFormat(Vendor.ASN1)
                            .setDecryptor(createPKDecryptor(pem))
                            .build();
                    break;
                }
                case "DSA PRIVATE KEY": {
                    keyPair = new KeyPairDSA.Builder(config)
                            .setPrivateKey(pem.getContent())
                            .setFormat(Vendor.ASN1)
                            .setDecryptor(createPKDecryptor(pem))
                            .build();
                    break;
                }
                case "EC PRIVATE KEY": {
                    keyPair = new KeyPairECDSA.Builder(config)
                            .setPrivateKey(pem.getContent())
                            .setFormat(Vendor.ASN1)
                            .setDecryptor(createPKDecryptor(pem))
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
                default:
                    throw new InvalidKeyException("Invalid private key");
            }
        }

        if (pubKeyReader != null) {
            readPublicKey(pubKeyReader, keyPair, true);
        }
        return keyPair;
    }

    private void readPublicKey(@NonNull final BufferedReader pubKeyReader,
                               @NonNull final SshKeyPair keyPair,
                               final boolean readKey)
            throws IOException, InvalidKeyException {
        try (PemReader reader = new PemReader(pubKeyReader)) {
            reader.mark(32);
            @Nullable final String line = reader.readLine();
            if (line != null) {
                reader.reset();
                if (line.startsWith("-----BEGIN PUBLIC KEY")) {
                    parsePublicKeyFromPem(reader, keyPair, readKey);
                } else {
                    parsePublicKeyFromSingleLine(reader, keyPair, readKey);
                }
            }
        }
    }

    /**
     * Continue parsing for the public key in PEM format.
     *
     * @param reader  to read from
     * @param keyPair the KeyPair to update
     */
    private void parsePublicKeyFromPem(@NonNull final PemReader reader,
                                       @NonNull final SshKeyPair keyPair,
                                       final boolean readKey)
            throws IOException, InvalidKeyException {

        final PemObject pem = reader.readPemObject();
        if (pem == null) {
            throw new InvalidKeyException("Invalid public key");
        }

        if (readKey) {
            keyPair.setSshPublicKeyBlob(pem.getContent());
        }

        //noinspection unchecked
        ((List<PemHeader>) pem.getHeaders())
                .stream()
                .filter(h -> "Comment".equalsIgnoreCase(h.getName()))
                .map(PemHeader::getValue)
                .findFirst()
                .ifPresent(keyPair::setPublicKeyComment);
    }

    /**
     * Continue parsing for the public key in "type base64publickey comment" format.
     *
     * @param reader  to read from
     * @param keyPair the KeyPair to update
     */
    private void parsePublicKeyFromSingleLine(@NonNull final PemReader reader,
                                              @NonNull final SshKeyPair keyPair,
                                              final boolean readKey)
            throws IOException, InvalidKeyException {
        // skip blank lines and any comments
        String line;
        do {
            line = reader.readLine();
        } while (line != null && (line.isBlank() || line.trim().charAt(0) == '#'));

        if (line != null) {
            final String[] parts = line.split(" ");
            if (parts.length > 1) {
                if (readKey) {
                    // part 0 is the type; don't need it - we get the type from the private key
                    // part 1 is the base64 encoded public key
                    try {
                        keyPair.setSshPublicKeyBlob(Base64.getDecoder()
                                                          .decode(parts[1].trim()));

                    } catch (final IllegalArgumentException e) {
                        throw new InvalidKeyException("Invalid base64 data for public key", e);
                    }
                }
                // any subsequent parts are comment
                if (parts.length > 2) {
                    final StringBuilder comment = new StringBuilder();
                    for (int i = 2; i < parts.length; i++) {
                        comment.append(parts[i]);
                    }
                    keyPair.setPublicKeyComment(comment.toString());
                }
            }
        }
    }

    @Nullable
    private PKDecryptor createPKDecryptor(@NonNull final PemObject pem)
            throws InvalidKeyException, NoSuchAlgorithmException {
        //noinspection unchecked
        for (final PemHeader header : (List<PemHeader>) pem.getHeaders()) {
            if ("DEK-Info".equals(header.getName())) {
                // DEK-Info: AES-128-CBC,D54228DB5838E32589695E83A22595C7
                // The cipher names are (of course) different from what we need.
                // The encryption algorithm name is as used by OpenSSL EVP_get_cipherbyname()
                // As this header type is (August 2021) ancient, we're not doing much effort here...
                final String[] values = header.getValue().split(",");
                if (values.length == 2) {
                    final SshCipher cipher = ImplementationFactory
                            .getCipher(config, getSshCipherName(values[0]));
                    final byte[] iv = createIV(values[1], cipher.getIVSize());
                    // uses the iv as the salt
                    final PKDecryptor decryptor = new DecryptPKCS5().init("MD5", iv);
                    decryptor.setCipher(cipher, iv);
                    return decryptor;
                }
            }
        }
        return null;
    }

    @NonNull
    private String getSshCipherName(@NonNull final String headerValue)
            throws InvalidKeyException {
        final String sshName;
        switch (headerValue) {
            case "AES-128-CBC":
                sshName = "aes128-cbc";
                break;
            case "AES-192-CBC":
                sshName = "aes192-cbc";
                break;
            case "AES-256-CBC":
                sshName = "aes256-cbc";
                break;
            case "DES-EDE3-CBC":
                sshName = "3des-cbc";
                break;
            default:
                throw new InvalidKeyException("Invalid cipher");
        }
        return sshName;
    }

    @NonNull
    private byte[] createIV(@NonNull final String headerValue,
                            final int ivSize) throws InvalidKeyException {
        final byte[] iv = new byte[ivSize];
        try {
            final byte[] bytes = headerValue.getBytes(StandardCharsets.UTF_8);
            int b = 0;
            for (int i = 0; i < iv.length; i++) {
                iv[i] = (byte) (((Character.digit(bytes[b++], 16) << 4) & 0xf0)
                        | Character.digit(bytes[b++], 16) & 0x0f);
            }
        } catch (final IllegalArgumentException e) {
            throw new InvalidKeyException("Invalid IV");
        }
        return iv;
    }
}
