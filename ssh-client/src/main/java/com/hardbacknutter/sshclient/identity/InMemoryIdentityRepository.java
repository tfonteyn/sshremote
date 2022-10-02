package com.hardbacknutter.sshclient.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The default in-memory repository.
 */
public class InMemoryIdentityRepository
        implements IdentityRepository {

    private static final String name = "In-memory Identity Repository";

    private final List<Identity> identities = new ArrayList<>();


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

            final byte[] blob1 = identity.getPublicKeyBlob();
            if (blob1 == null) {
                identities.add(identity);
                return true;
            }

            for (final Identity idi : identities) {
                final byte[] blob2 = idi.getPublicKeyBlob();
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
            return remove(identity.getPublicKeyBlob());
        }
    }

    @Override
    public synchronized boolean remove(@Nullable final byte[] publicKeyBlob)
            throws GeneralSecurityException {
        if (publicKeyBlob == null) {
            return false;
        }
        for (final Identity identity : identities) {
            final byte[] blob = identity.getPublicKeyBlob();
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
            final Identity foo = identities.get(i);

            final byte[] foo_blob = foo.getPublicKeyBlob();
            if (foo_blob != null) {
                for (int j = i + 1; j < len; j++) {

                    final Identity bar = identities.get(j);
                    final byte[] bar_blob = bar.getPublicKeyBlob();
                    if (bar_blob != null) {
                        if (Arrays.equals(foo_blob, bar_blob) &&
                                foo.isEncrypted() == bar.isEncrypted()) {
                            toRemove.add(foo_blob);
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
