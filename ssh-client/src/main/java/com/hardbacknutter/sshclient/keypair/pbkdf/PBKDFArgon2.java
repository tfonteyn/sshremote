package com.hardbacknutter.sshclient.keypair.pbkdf;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ciphers.SshCipher;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.util.Arrays;

import javax.crypto.Cipher;


@SuppressWarnings("NotNullFieldNotInitialized")
public class PBKDFArgon2 implements PBKDF {

    private static final byte[] Z_BYTE_ARRAY = new byte[0];

    private int macLength;

    @NonNull
    private Argon2BytesGenerator generator;

    @Nullable
    private SshCipher cipher;
    @Nullable
    private byte[] cipherIV;

    /**
     * Init.
     *
     * @param keyDerivation  String for the Argon2 key derivation type.
     *                       One of "Argon2d", "Argon2i" or "Argon2id".
     * @param salt           the salt.
     * @param iterationCount the iteration count.
     */
    public PBKDFArgon2 init(@NonNull final String keyDerivation,
                            @NonNull final String memoryAsKB,
                            @NonNull final String iterationCount,
                            @NonNull final String parallelism,
                            @NonNull final String salt,
                            final int macLength)
            throws KeyException {

        this.macLength = macLength;

        final int type;
        switch (keyDerivation) {
            case "Argon2d":
                type = Argon2Parameters.ARGON2_d;
                break;
            case "Argon2i":
                type = Argon2Parameters.ARGON2_i;
                break;
            case "Argon2id":
                type = Argon2Parameters.ARGON2_id;
                break;
            default:
                throw new KeyException("Invalid Key-Derivation: " + keyDerivation);
        }
        final int memory;
        final int iterationCount1;
        final int parallelism1;
        final byte[] salt1;
        try {
            memory = Integer.parseInt(memoryAsKB);
            iterationCount1 = Integer.parseInt(iterationCount);
            parallelism1 = Integer.parseInt(parallelism);
            salt1 = new byte[salt.length() / 2];
            for (int i = 0; i < salt1.length; i++) {
                final int j = i * 2;
                salt1[i] = (byte) Integer.parseInt(salt.substring(j, j + 2), 16);
            }
        } catch (@NonNull final NumberFormatException e) {
            throw new KeyException(e);
        }

        final Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .withMemoryAsKB(memory)
                .withIterations(iterationCount1)
                .withParallelism(parallelism1)
                .withSalt(salt1)
                //  a secret key, and some ‘associated data’.
                //  In PPK's use of Argon2, these are both set
                //  to the empty string.
                .withSecret(Z_BYTE_ARRAY)
                .withAdditional(Z_BYTE_ARRAY)
                .build();

        generator = new Argon2BytesGenerator();
        generator.init(parameters);

        return this;
    }

    @Override
    public void setCipher(@Nullable final SshCipher cipher,
                          @Nullable final byte[] cipherIV) {
        this.cipher = cipher;
        this.cipherIV = cipherIV;
    }

    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    final int keyLength) {

        final byte[] key = new byte[keyLength];
        generator.generateBytes(passphrase, key);
        return key;
    }

    @NonNull
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException {
        if (cipher == null || cipherIV == null) {
            throw new KeyException("Cipher/iv not set");
        }

        byte[] pbeKey = null;
        try {
            // from the Putty docs:
            // encryption-type is ‘aes256-cbc’, then the symmetric cipher key
            // is 32 bytes long, and the initialisation vector is 16 bytes
            // (one cipher block).
            // The length of the MAC key is also chosen to be 32 bytes.

            byte[] tmp = new byte[cipher.getKeySize() + cipher.getIVSize() + macLength];
            // The output data is interpreted as the concatenation of the cipher key,
            // the IV and the MAC key, in that order.
            tmp = generateSecretKey(passphrase, tmp.length);

            pbeKey = new byte[cipher.getKeySize()];
            System.arraycopy(tmp, 0, pbeKey, 0, cipher.getKeySize());
            System.arraycopy(tmp, cipher.getKeySize(), cipherIV, 0, cipherIV.length);

            final byte[] plainKey = new byte[blob.length];
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(blob, 0, blob.length, plainKey, 0);
            return plainKey;
        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
            Arrays.fill(passphrase, (byte) 0);
        }
    }
}
