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
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPKCS8;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

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
     * Creates a new key pair.
     *
     * @param keyType ed25519 | ed448
     *
     * @return the new key pair.
     */
    @NonNull
    public SshKeyPair generateKeyPair(@NonNull final String keyType)
            throws GeneralSecurityException {
        switch (keyType.toLowerCase(Locale.ENGLISH)) {
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
     *
     * @param privateKeyFilename the file name of the private key file.
     *                           The public key is expected in a file with the same name
     *                           and suffix {@code .pub}.
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
     *
     * @param privateKeyFilename the file name of the private key file.
     * @param publicKeyFilename  the file name of the public key file.
     *
     * @return the new KeyPair.
     */
    @NonNull
    public SshKeyPair load(@NonNull final String privateKeyFilename,
                           @Nullable final String publicKeyFilename)
            throws IOException, GeneralSecurityException {

        //TODO: Android API 26 limitation
        //noinspection ImplicitDefaultCharsetUsage
        final BufferedReader prvKeyReader = new BufferedReader(
                // new FileReader(privateKeyFilename, StandardCharsets.UTF_8));
                new FileReader(privateKeyFilename));

        final BufferedReader pubKeyReader;
        if (publicKeyFilename != null) {
            //TODO: Android API 26 limitation
            //noinspection ImplicitDefaultCharsetUsage
            pubKeyReader = new BufferedReader(
                    // new FileReader(publicKeyFilename, StandardCharsets.UTF_8));
                    new FileReader(publicKeyFilename));
        } else {
            pubKeyReader = null;
        }

        return load(prvKeyReader, pubKeyReader);
    }

    @NonNull
    public SshKeyPair load(@NonNull final byte[] prvKey,
                           @Nullable final byte[] pubKey)
            throws IOException, GeneralSecurityException {

        // Check for binary format key from "ssh-add" command on the remote.
        if (SshAgentReader.isSSHAgent(prvKey, pubKey)) {
            final SshAgentReader sshAgentReader = new SshAgentReader(config);
            return sshAgentReader.parse(prvKey);
        }

        final BufferedReader prvKeyReader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(prvKey),
                                      StandardCharsets.UTF_8));
        final BufferedReader pubKeyReader;
        if (pubKey != null) {
            pubKeyReader = new BufferedReader(
                    new InputStreamReader(new ByteArrayInputStream(pubKey),
                                          StandardCharsets.UTF_8));
        } else {
            pubKeyReader = null;
        }

        return load(prvKeyReader, pubKeyReader);
    }

    /**
     * Loads a key pair from a pair of BufferedReader.
     * They MUST be BufferedReader as we'll need to use mark/reset.
     *
     * @return the new KeyPair.
     */
    @NonNull
    public SshKeyPair load(@NonNull final BufferedReader prvKeyReader,
                           @Nullable final BufferedReader publicKeyReader)
            throws IOException, GeneralSecurityException {

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

            switch (pem.getType()) {
                case "OPENSSH PRIVATE KEY": {
                    // current openssh v1 default
                    final OpenSSHv1Reader parser = new OpenSSHv1Reader(config);
                    keyPair = parser.parse(pem.getContent());
                    if (keyPair != null) {
                        // all done, the public key was embedded in the privateKeyBlob
                        // We silently ignore the 'pubKey' which might have a 'comment' ...
                        return keyPair;
                    } else {
                        throw new InvalidKeyException("Invalid OpenSSHv1 format");
                    }
                }
                case "RSA PRIVATE KEY": {
                    // legacy openssh rsa pem
                    final PKDecryptor decryptor = createPKDecryptor(pem);
                    keyPair = new KeyPairRSA.Builder(config)
                            .setPrivateKeyBlob(pem.getContent(), Vendor.PKCS5, decryptor)
                            .build();
                    break;
                }
                case "DSA PRIVATE KEY": {
                    // legacy openssh dsa pem
                    final PKDecryptor decryptor = createPKDecryptor(pem);
                    keyPair = new KeyPairDSA.Builder(config)
                            .setPrivateKeyBlob(pem.getContent(), Vendor.PKCS5, decryptor)
                            .build();
                    break;
                }
                case "EC PRIVATE KEY": {
                    // legacy openssh ec pem
                    // The type will be one of (currently) 3: ECDSA 256/384/521
                    // We'll find out at a later stage in parsing.
                    final PKDecryptor decryptor = createPKDecryptor(pem);
                    keyPair = new KeyPairECDSA.Builder(config)
                            .setPrivateKeyBlob(pem.getContent(), Vendor.PKCS5, decryptor)
                            .build();
                    break;
                }
                case "ENCRYPTED PRIVATE KEY":
                case "PRIVATE KEY": {
                    // SSL style PKCS8 wrapper
                    final PKDecryptor decryptor = new DecryptPKCS8(config);
                    keyPair = new KeyPairPKCS8.Builder(config)
                            .setPrivateKeyBlob(pem.getContent(), Vendor.PKCS8, decryptor)
                            .build();
                    break;
                }
                default:
                    throw new InvalidKeyException("Invalid private key");
            }
        }

        if (publicKeyReader == null) {
            return keyPair;
        }

        //TODO (perhaps...) the below assumes that the key/pem starts on line 1
        try (PemReader reader = new PemReader(publicKeyReader)) {
            reader.mark(32);
            final String line = reader.readLine();
            if (line.startsWith("-----BEGIN PUBLIC KEY")) {
                reader.reset();
                final PemObject pem = reader.readPemObject();
                if (pem == null) {
                    throw new InvalidKeyException("Invalid public key");
                }

                keyPair.setSshPublicKeyBlob(pem.getContent());
                //noinspection unchecked
                final Optional<String> optionalComment =
                        ((List<PemHeader>) pem.getHeaders())
                                .stream()
                                .filter(h -> "Comment".equalsIgnoreCase(h.getName()))
                                .map(PemHeader::getValue)
                                .findFirst();
                if (optionalComment.isPresent()) {
                    keyPair.setPublicKeyComment(optionalComment.get());
                }

            } else {
                // try format: "type base64publickey comment"
                final String[] parts = line.split(" ");
                if (parts.length > 1) {
                    // part 0 is the type; don't need it - we get the type from the private key
                    // part 1 is the base64 key
                    try {
                        keyPair.setSshPublicKeyBlob(Base64.getDecoder().decode(parts[1].trim()));

                    } catch (final IllegalArgumentException e) {
                        throw new InvalidKeyException("Invalid base64 data for public key", e);
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
        return keyPair;
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

                    final PKDecryptor decryptor = new DecryptPKCS5();
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
