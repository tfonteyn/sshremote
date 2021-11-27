package com.hardbackcollector.sshclient.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.utils.SshException;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * We'll accept encrypted keys, but some implementations of
 * IdentityRepository can not.  For example, IdentityRepository for
 * ssh-agent only accepts plain keys.  The following class has
 * been introduced to cache encrypted keys for them, and pass them
 * whenever they are decrypted.
 */
public class IdentityRepositoryWrapper
        implements IdentityRepository {

    @NonNull
    private final IdentityRepository repository;
    private final List<Identity> cache = new ArrayList<>();
    private final boolean cacheEnabled;

    public IdentityRepositoryWrapper(@NonNull final IdentityRepository repository,
                                     final boolean enableCaching) {
        this.repository = repository;
        this.cacheEnabled = enableCaching;
    }

    /**
     * Pass-through operation.
     */
    @NonNull
    public String getName() {
        return repository.getName();
    }

    @Override
    public boolean supportsEncryption() {
        return true;
    }

    /**
     * Pass-through operation.
     */
    public boolean remove(@Nullable final byte[] publicKeyBlob)
            throws SshException, GeneralSecurityException {
        return repository.remove(publicKeyBlob);
    }

    /**
     * Remove from cache and pass-through request to the wrapped repo.
     */
    public void removeAll()
            throws SshException {
        cache.clear();
        repository.removeAll();
    }

    /**
     * Returns the content of the cache appended with the wrapped repo identities.
     */
    @NonNull
    public List<Identity> getIdentities()
            throws GeneralSecurityException {
        final List<Identity> result = new ArrayList<>(cache);
        result.addAll(repository.getIdentities());
        return result;
    }

    public boolean add(@NonNull final Identity identity) {

        if (!cacheEnabled
                && (!identity.isEncrypted() || repository.supportsEncryption())) {
            try {
                repository.add(identity);

            } catch (final GeneralSecurityException ignore) {
                // don't throw, just do not add the identity
                return false;
            }
        } else {
            // otherwise just keep it in our in-memory cache.
            cache.add(identity);

        }
        return true;
    }

    /**
     * refresh the cache
     */
    @Override
    public void update(@NonNull final Identity identity) {
        cache.remove(identity);
        add(identity);
    }
}
