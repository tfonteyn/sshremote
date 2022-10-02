package com.hardbacknutter.sshclient.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.utils.SshException;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A repository for identities (basically key pairs usable for authentication to a server).
 * The default implementation included in the library contains just a list of keys in memory,
 * but other implementations can be provided by the application, using e.g. a hardware storage
 * or external apps like ssh-agent.
 *
 * @see SshClient#setIdentityRepository(IdentityRepository)
 * @see SshClient#getIdentityRepository()
 * @see Session#setIdentityRepository(IdentityRepository)
 * @see Session#getIdentityRepository()
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-7">
 * RFC 4252 SSH Authentication Protocol,
 * section 7. Public Key Authentication Method: "publickey"</a>
 */
public interface IdentityRepository {

    /**
     * Get the name of the repository instance.
     * Information/display purposes only.
     *
     * @return the name of this repository
     */
    @NonNull
    String getName();

    /**
     * Returns all the identities of this repository.
     *
     * @return a List of {@link Identity} objects.
     */
    @NonNull
    List<Identity> getIdentities()
            throws GeneralSecurityException;

    /**
     * Lists names of identities included in the identityRepository.
     *
     * @return a List of the names of the identities
     */
    @NonNull
    default List<String> getIdentityNames()
            throws GeneralSecurityException {
        return getIdentities()
                .stream()
                .map(Identity::getName)
                .collect(Collectors.toList());
    }

    /**
     * Adds a new identity to this repository.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     */
    boolean add(@NonNull Identity identity)
            throws GeneralSecurityException;

    void update(@NonNull Identity identity)
            throws GeneralSecurityException;

    /**
     * Removes an identity from the repository, given the public key.
     *
     * @param publicKeyBlob the identity's public key, encoded as a byte[].
     *
     * @return {@code true} if there was an identity with the given key to be removed,
     * {@code false} otherwise.
     *
     * @throws SshException if the IdentityRepository has problems.
     */
    boolean remove(@Nullable byte[] publicKeyBlob)
            throws SshException, GeneralSecurityException;

    /**
     * Removes an identity from identityRepository.
     *
     * @param identity the identity to be removed.
     *
     * @return {@code true} if there was an identity with the given key to be removed,
     * {@code false} otherwise.
     *
     * @throws SshException if the IdentityRepository has problems.
     */
    default boolean remove(@NonNull final Identity identity)
            throws SshException, GeneralSecurityException {
        return remove(identity.getPublicKeyBlob());
    }

    /**
     * Removes all identities. Public key authentication will not
     * work anymore until another identity is added.
     *
     * @throws SshException if the IdentityRepository has problems.
     */
    void removeAll()
            throws SshException;

    /**
     * Whether this repository supports encrypted keys.
     *
     * @return {@code false} by default
     */
    default boolean supportsEncryption() {
        return false;
    }
}
