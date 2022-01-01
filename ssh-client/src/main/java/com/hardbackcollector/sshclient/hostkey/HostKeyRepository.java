package com.hardbackcollector.sshclient.hostkey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.userauth.UserInfo;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.List;

/**
 * A repository for known host keys.
 * This will be used when connecting remote servers to check that their
 * public keys are the same as we think they should be.
 * <p>
 * The library contains an implementation {@link KnownHosts}
 * based on the OpenSSH known Hosts file format - this will be the
 * default implementation if no other is given explicitly.
 * <p>
 * An application might want to implement this class to provide an
 * alternative repository of valid server keys to use.
 *
 * @see SshClient#setHostKeyRepository
 */
public interface HostKeyRepository {

    /**
     * Create a host key by guessing it's type from the data.
     * <p>
     * Overriding this method allows the repository to apply specific rules/settings.
     * Example: {@link KnownHosts} can decide whether to hash the key or not.
     *
     * @param host the host name
     * @param key  the key data.
     *
     * @return instance
     */
    @SuppressWarnings("OverlyBroadThrowsClause")
    @NonNull
    default HostKey createHostKey(@NonNull final SshClient sshClient,
                                  @NonNull final String host,
                                  @NonNull final byte[] key)
            throws GeneralSecurityException {
        return new HostKey(host, key);
    }

    /**
     * Checks whether some host has a given key.
     *
     * @param host                   the host name to check
     * @param serverHostKeyAlgorithm the key algorithm of the remote host
     * @param key                    the public key of the remote host
     *
     * @return one of the {@link KeyIs} values
     *
     * @throws InvalidKeyException if the provided key blob is not recognized
     */
    @NonNull
    KeyIs isKnown(@NonNull String host,
                  @NonNull String serverHostKeyAlgorithm,
                  @NonNull byte[] key)
            throws InvalidKeyException;

    /**
     * Adds a hostname-key-pair to the repository.
     *
     * @param hostKey the key to add
     * @param ui      an UserInfo object which may be used to ask the
     *                user whether to create the file (and directory), or other
     *                similar questions, if necessary.
     */
    void add(@NonNull HostKey hostKey,
             @Nullable UserInfo ui);

    /**
     * Removes a specific key of a host from the repository.
     *
     * @param host the host name whose key is to remove.
     * @param type the type of key to remove. If {@code null}, all keys of
     *             this host will be removed (without looking at {@code key}).
     * @param key  the key to be removed. If {@code null}, all keys of the
     *             given type and host will be removed.
     */
    void remove(@NonNull final String host,
                @Nullable final String type,
                @Nullable final byte[] key);

    /**
     * returns an identifier for this repository.
     * This could be the file name of the file being accessed, for example.
     * <p>
     * This will be used for messages to the user speaking about the repository.
     */
    @Nullable
    String getRepositoryID();

    /**
     * Returns a list for host keys managed in this repository.
     *
     * @see #getHostKeys(String host, String type)
     */
    @NonNull
    default List<HostKey> getHostKeys() {
        return getHostKeys(null, null);
    }

    /**
     * Returns a list for host keys managed in this repository.
     *
     * @param host a hostname or alias used to lookup host keys.
     *             If {@code null} is given, every host key will be listed.
     * @param type a key type used to lookup host keys
     *             If {@code null} is given, a key type type will not be ignored.
     */
    @NonNull
    List<HostKey> getHostKeys(@Nullable final String host,
                              @Nullable final String type);

    enum KeyIs {
        /**
         * The host does not exist yet in the list.
         */
        Unknown,
        /**
         * The host has another key. (This could be indicating a man-in-the-middle attack.)
         */
        Changed,
        /**
         * The host key was known and approved.
         */
        Accepted,
        /**
         * The host key was known but previously revoked.
         */
        Revoked
    }
}
