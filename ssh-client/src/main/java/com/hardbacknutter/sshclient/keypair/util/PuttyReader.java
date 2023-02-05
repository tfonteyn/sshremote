package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.ECKeyType;
import com.hardbacknutter.sshclient.keypair.KeyPairDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairECDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairEdDSA;
import com.hardbacknutter.sshclient.keypair.KeyPairRSA;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.Vendor;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPutty2;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPutty3;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.ECPoint;
import java.util.Base64;


/**
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk">
 * PPK file format</a>
 * @see <a href="https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixC.html#ppk-v2">
 * PPK version 2 file format</a>
 */
class PuttyReader {

    private static final String AES_256_CBC = "aes256-cbc";
    @NonNull
    private final SshClientConfig config;

    private final Base64.Decoder b64 = Base64.getDecoder();

    /**
     * Constructor.
     */
    PuttyReader(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Loads a key pair from a PuTTY file.
     *
     * @param reader MUST be a BufferedReader as we'll need to use mark/reset.
     *
     * @return the new KeyPair.
     */
    @Nullable
    SshKeyPair parse(@NonNull final BufferedReader reader)
            throws IOException, GeneralSecurityException {

        reader.mark(32);

        Vendor privateKeyFormat = null;
        // First line identifies content and format version
        String line = reader.readLine();
        if (line != null) {
            if (line.startsWith("PuTTY-User-Key-File-2")) {
                privateKeyFormat = Vendor.PUTTY_V2;
            } else if (line.startsWith("PuTTY-User-Key-File-3")) {
                privateKeyFormat = Vendor.PUTTY_V3;
            } else {
                reader.reset();
                return null;
            }
        }

        String encryption = null;
        String argonKeyDerivation = null;
        String argonMemory = null;
        String argonPasses = null;
        String argonParallelism = null;
        String argonSalt = null;

        String publicKeyComment = "";

        byte[] privateKeyBlob = null;
        byte[] publicKeyBlob = null;

        while ((line = reader.readLine()) != null) {
            final String value = line.substring(line.indexOf(':') + 2).trim();

            if (line.startsWith("Encryption: ")) {
                if ("none".equals(value)) {
                    encryption = null;
                } else if (AES_256_CBC.equals(value)) {
                    encryption = value;
                }

            } else if (line.startsWith("Comment: ")) {
                publicKeyComment = value;

            } else if (line.startsWith("Public-Lines: ")) {
                publicKeyBlob = parseBase64(reader, line);

            } else if (line.startsWith("Private-Lines: ")) {
                privateKeyBlob = parseBase64(reader, line);

            } else if (line.startsWith("Key-Derivation: ")) {
                argonKeyDerivation = value;
            } else if (line.startsWith("Argon2-Memory: ")) {
                argonMemory = value;
            } else if (line.startsWith("Argon2-Passes: ")) {
                argonPasses = value;
            } else if (line.startsWith("Argon2-Parallelism: ")) {
                argonParallelism = value;
            } else if (line.startsWith("Argon2-Salt: ")) {
                argonSalt = value;
            }
        }

        if (publicKeyBlob == null || privateKeyBlob == null) {
            return null;
        }

        final PKDecryptor decryptor;
        if (AES_256_CBC.equals(encryption)) {
            if (privateKeyFormat == Vendor.PUTTY_V3) {
                // from the Putty docs:
                // encryption-type is ‘aes256-cbc’,
                // ... The length of the MAC key is also chosen to be 32 bytes.
                decryptor = new DecryptPutty3().init(argonKeyDerivation,
                                                     argonMemory, argonPasses, argonParallelism,
                                                     argonSalt,
                                                     32);
            } else {
                decryptor = new DecryptPutty2().init();
            }
            final SshCipher cipher = ImplementationFactory.getCipher(config, encryption);
            decryptor.setCipher(cipher);

        } else {
            decryptor = null;
        }

        final Buffer buffer = new Buffer(publicKeyBlob);
        final String hostKeyAlgorithm = buffer.getJString();
        switch (hostKeyAlgorithm) {
            case HostKeyAlgorithm.SSH_RSA: {
                final BigInteger publicExponent = buffer.getBigInteger();
                final BigInteger modulus = buffer.getBigInteger();

                final SshKeyPair keyPair = new KeyPairRSA.Builder(config)
                        .setPublicExponent(publicExponent)
                        .setModulus(modulus)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(privateKeyFormat)
                        .setDecryptor(decryptor)
                        .build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_DSS: {
                final BigInteger p = buffer.getBigInteger();
                final BigInteger q = buffer.getBigInteger();
                final BigInteger g = buffer.getBigInteger();
                final BigInteger y = buffer.getBigInteger();

                final SshKeyPair keyPair = new KeyPairDSA.Builder(config)
                        .setPQG(p, q, g)
                        .setY(y)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(privateKeyFormat)
                        .setDecryptor(decryptor)
                        .build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
            case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521: {
                buffer.skipString(/* nistName */);

                final ECPoint w = ECKeyType.decodePoint(buffer.getString());

                final SshKeyPair keyPair = new KeyPairECDSA.Builder(config)
                        .setType(ECKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm))
                        .setPoint(w)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(privateKeyFormat)
                        .setDecryptor(decryptor)
                        .build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            case HostKeyAlgorithm.SSH_ED25519:
            case HostKeyAlgorithm.SSH_ED448: {
                final byte[] pubArray = buffer.getString();

                final SshKeyPair keyPair = new KeyPairEdDSA.Builder(config)
                        .setType(hostKeyAlgorithm)
                        .setPubArray(pubArray)
                        .setPrivateKey(privateKeyBlob)
                        .setFormat(privateKeyFormat)
                        .setDecryptor(decryptor)
                        .build();
                keyPair.setPublicKeyComment(publicKeyComment);
                return keyPair;
            }
            default:
                return null;
        }
    }

    @NonNull
    private byte[] parseBase64(@NonNull final BufferedReader br,
                               @NonNull String line)
            throws IOException, InvalidKeyException {
        final int lines = Integer.parseInt(line.substring(line.indexOf(':') + 2).trim());
        final StringBuilder bs = new StringBuilder();
        for (int i = 0; i < lines; i++) {
            line = br.readLine();
            if (line == null) {
                throw new InvalidKeyException("Not enough lines");
            }
            bs.append(line);
        }
        return b64.decode(bs.toString());
    }
}
