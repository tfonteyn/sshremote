package com.hardbackcollector.sshclient.hostkey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Random;
import com.hardbackcollector.sshclient.macs.SshMac;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;

class HashedHostKey
        extends HostKey {

    private static final String HASH_MAGIC = "|1|";
    private static final String HASH_DELIM = "|";
    @NonNull
    private final SshMac mac;
    @Nullable
    private byte[] salt;
    @Nullable
    private byte[] hash;
    private boolean hashed;

    HashedHostKey(@NonNull final SshMac mac,
                  @NonNull final String host,
                  @NonNull final byte[] key)
            throws InvalidKeyException {
        this(mac, "", host, null, key, null);
    }

    HashedHostKey(@NonNull final SshMac mac,
                  @NonNull final String marker,
                  @NonNull final String host,
                  @Nullable final String type,
                  @Nullable final byte[] key,
                  @Nullable final String comment)
            throws InvalidKeyException {
        super(marker, host, type, key, comment);

        this.mac = mac;

        if (hostnames.startsWith(HASH_MAGIC) &&
                hostnames.substring(HASH_MAGIC.length()).indexOf(HASH_DELIM) > 0) {

            final String data = hostnames.substring(HASH_MAGIC.length());
            final Base64.Decoder decoder = Base64.getDecoder();

            final byte[] _salt = decoder.decode(
                    data.substring(0, data.indexOf(HASH_DELIM))
                        .getBytes(StandardCharsets.UTF_8));

            final byte[] _hash = decoder.decode(
                    data.substring(data.indexOf(HASH_DELIM) + 1)
                        .getBytes(StandardCharsets.UTF_8));

            if (_salt.length != mac.getDigestLength() ||
                    _hash.length != mac.getDigestLength()) {
                salt = null;
                hash = null;
                hashed = false;
            } else {
                salt = _salt;
                hash = _hash;
                hashed = true;
            }
        }
    }

    /**
     * Check if the given hostname matches any of the keys hostnames.
     *
     * @param host to check
     *
     * @return whether they match or {@code false} on any error.
     */
    public boolean isMatching(@NonNull final String host) {
        if (!hashed) {
            return super.isMatching(host);
        }
        // If it is hashed, then the salt will already be initialized.
        try {
            synchronized (mac) {
                //noinspection ConstantConditions
                mac.init(salt);
                final byte[] in = host.getBytes(StandardCharsets.UTF_8);
                mac.update(in, 0, in.length);
                final byte[] out = new byte[mac.getDigestLength()];
                mac.doFinal(out, 0);

                return Arrays.equals(hash, out);
            }
        } catch (final Exception ignore) {
        }
        return false;
    }

    boolean isHashed() {
        return hashed;
    }

    void hash(@NonNull final Random random)
            throws GeneralSecurityException {
        if (hashed) {
            return;
        }
        if (salt == null) {
            salt = random.nextBytes(mac.getDigestLength());
        }

        synchronized (mac) {
            mac.init(salt);
            final byte[] in = hostnames.getBytes(StandardCharsets.UTF_8);
            mac.update(in, 0, in.length);
            hash = new byte[mac.getDigestLength()];
            mac.doFinal(hash, 0);
        }

        final Base64.Encoder encoder = Base64.getEncoder();
        final byte[] encHash = encoder.encode(hash);
        final byte[] encSalt = encoder.encode(salt);
        hostnames = HASH_MAGIC + new String(encSalt, 0, encSalt.length, StandardCharsets.UTF_8) +
                HASH_DELIM + new String(encHash, 0, encHash.length, StandardCharsets.UTF_8);

        hashed = true;
    }
}
