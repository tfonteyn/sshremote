package com.hardbacknutter.sshclient.identity;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.hardbacknutter.sshclient.SshClientConfig;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The default in-memory repository.
 */
public class InMemoryIdentityRepository
        implements IdentityRepository {

    private static final String name = "In-memory Identity Repository";

    private final List<Identity> identities = new ArrayList<>();


    /**
     * Constructor.
     *
     * @param config to use
     */
    public InMemoryIdentityRepository(@SuppressWarnings("unused")
                                      @NonNull final SshClientConfig config) {
    }

    @Override
    @NonNull
    public String getName() {
        return name;
    }

    @Override
    public boolean supportsEncryption() {
        return true;
    }

    @Override
    @NonNull
    public synchronized List<Identity> getIdentities()
            throws GeneralSecurityException {
        removeDuplicates();
        return new ArrayList<>(identities);
    }

    @Override
    public void update(@NonNull final Identity identity)
            throws GeneralSecurityException {
        // add it if not already there
        add(identity);
    }

    public synchronized boolean add(@NonNull final Identity identity)
            throws GeneralSecurityException {
        if (!identities.contains(identity)) {

            final byte[] blob1 = identity.getSshEncodedPublicKey();
            if (blob1 == null) {
                identities.add(identity);
                return true;
            }

            for (final Identity idi : identities) {
                final byte[] blob2 = idi.getSshEncodedPublicKey();
                if (blob2 != null && Arrays.equals(blob1, blob2)) {
                    if (!identity.isEncrypted() && idi.isEncrypted()) {
                        remove(blob2);
                    } else {
                        return true;
                    }
                }
            }

            identities.add(identity);
        }
        return true;
    }


    public synchronized boolean remove(@NonNull final Identity identity)
            throws GeneralSecurityException {
        if (identities.remove(identity)) {
            identity.clear();
            return true;
        } else {
            return remove(identity.getSshEncodedPublicKey());
        }
    }

    @Override
    public synchronized boolean remove(final byte @Nullable [] publicKeyBlob)
            throws GeneralSecurityException {
        if (publicKeyBlob == null) {
            return false;
        }
        for (final Identity identity : identities) {
            final byte[] blob = identity.getSshEncodedPublicKey();
            if (blob != null && Arrays.equals(publicKeyBlob, blob)) {
                identities.remove(identity);
                identity.clear();
                return true;
            }
        }
        return false;
    }

    @Override
    public synchronized void removeAll() {
        for (final Identity identity : identities) {
            identity.clear();
        }
        identities.clear();
    }

    private void removeDuplicates()
            throws GeneralSecurityException {

        final int len = identities.size();
        if (len == 0) {
            return;
        }

        final List<byte[]> toRemove = new ArrayList<>();

        for (int i = 0; i < len; i++) {
            final Identity identity1 = identities.get(i);
            final byte[] identity1blob = identity1.getSshEncodedPublicKey();

            if (identity1blob != null) {
                for (int j = i + 1; j < len; j++) {
                    final Identity identity2 = identities.get(j);
                    final byte[] identity2blob = identity2.getSshEncodedPublicKey();

                    if (identity2blob != null) {
                        if (Arrays.equals(identity1blob, identity2blob) &&
                            identity1.isEncrypted() == identity2.isEncrypted()) {
                            toRemove.add(identity1blob);
                            break;
                        }
                    }
                }
            }
        }
        for (int i = 0; i < toRemove.size(); i++) {
            remove(toRemove.get(i));
        }
    }
}
