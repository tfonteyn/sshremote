package com.hardbacknutter.sshclient.keypair.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.KeyPairBuilderFactory;
import com.hardbacknutter.sshclient.keypair.PrivateKeyEncoding;
import com.hardbacknutter.sshclient.keypair.PublicKeyEncoding;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFArgon2;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFPutty2;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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
     * @return the new KeyPair or {@code null} if not a ppk format
     */
    @Nullable
    SshKeyPair parse(@NonNull final BufferedReader reader)
            throws IOException, GeneralSecurityException {

        reader.mark(32);

        PrivateKeyEncoding privateKeyEncoding = null;
        // First line identifies content and format version
        String line = reader.readLine();
        if (line != null) {
            if (line.startsWith("PuTTY-User-Key-File-2")) {
                privateKeyEncoding = PrivateKeyEncoding.PUTTY_V2;
            } else if (line.startsWith("PuTTY-User-Key-File-3")) {
                privateKeyEncoding = PrivateKeyEncoding.PUTTY_V3;
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

        final PBKDF decryptor;
        if (AES_256_CBC.equals(encryption)) {
            if (privateKeyEncoding == PrivateKeyEncoding.PUTTY_V3) {
                // from the Putty docs:
                // encryption-type is ‘aes256-cbc’,
                // ... The length of the MAC key is also chosen to be 32 bytes.
                decryptor = new PBKDFArgon2().init(argonKeyDerivation,
                                                   argonMemory, argonPasses, argonParallelism,
                                                   argonSalt,
                                                   32);
            } else {
                decryptor = new PBKDFPutty2().init();
            }
            final SshCipher cipher = ImplementationFactory.getCipher(config, encryption);
            decryptor.setCipher(cipher);

        } else {
            decryptor = null;
        }

        final Buffer buffer = new Buffer(publicKeyBlob);
        final String hostKeyAlgorithm = buffer.getJString();

        final SshKeyPair keyPair = KeyPairBuilderFactory
                .byHostKeyAlgorithm(config, hostKeyAlgorithm)
                .setPrivateKey(privateKeyBlob, privateKeyEncoding)
                .setPublicKey(publicKeyBlob, PublicKeyEncoding.OPENSSH_V1)
                .setDecryptor(decryptor)
                .build();
        keyPair.setPublicKeyComment(publicKeyComment);
        return keyPair;
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
