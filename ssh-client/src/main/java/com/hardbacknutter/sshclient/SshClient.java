package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Map;

import com.hardbacknutter.sshclient.hostconfig.HostConfigRepository;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.userauth.SshAuthException;

public interface SshClient {

    @NonNull
    Logger getLogger();

    void setLogger(@Nullable Logger logger);

    void setConfig(@NonNull String key,
                   @NonNull String value);

    @NonNull
    SshClientConfig getConfig();

    void setConfig(@NonNull Map<String, String> newConf);

    @Nullable
    String getConfig(@NonNull String key);

    @SuppressWarnings("WeakerAccess")
    @Nullable
    HostConfigRepository getHostConfigRepository();

    @SuppressWarnings("WeakerAccess")
    void setHostConfigRepository(@Nullable HostConfigRepository configRepository);

    @SuppressWarnings("WeakerAccess")
    @NonNull
    HostKeyRepository getHostKeyRepository();

    void setHostKeyRepository(@Nullable HostKeyRepository repository);

    @SuppressWarnings("OverlyBroadThrowsClause")
    void setKnownHosts(@NonNull String filename)
            throws IOException, GeneralSecurityException;

    @SuppressWarnings("OverlyBroadThrowsClause")
    void setKnownHosts(@NonNull InputStream stream)
            throws IOException, GeneralSecurityException;

    @NonNull
    Session getSession(@NonNull String host)
            throws IOException, GeneralSecurityException, SshAuthException;

    @NonNull
    Session getSession(@Nullable String username,
                       @NonNull String host)
            throws SshAuthException, IOException, GeneralSecurityException;

    @NonNull
    Session getSession(@Nullable String username,
                       @NonNull String host,
                       int port)
            throws SshAuthException, IOException, GeneralSecurityException;

    @NonNull
    Session getSession(@Nullable String username,
                       @NonNull String host,
                       int port,
                       @Nullable String hostNameOrAlias)
            throws IOException, GeneralSecurityException, SshAuthException;

    @NonNull
    IdentityRepository getIdentityRepository();

    void setIdentityRepository(
            @Nullable IdentityRepository identityRepository);

    boolean addIdentity(@NonNull String privateKeyFilename)
            throws IOException, GeneralSecurityException;

    @SuppressWarnings("WeakerAccess")
    boolean addIdentity(@NonNull String privateKeyFilename,
                        @Nullable String publicKeyFilename,
                        @Nullable byte[] passphrase)
            throws IOException, GeneralSecurityException;

    @SuppressWarnings({"WeakerAccess", "unused"})
    boolean addIdentity(@NonNull String name,
                        @NonNull byte[] prvKey,
                        @Nullable byte[] pubKey,
                        @Nullable byte[] passphrase)
            throws IOException, GeneralSecurityException;

    boolean addIdentity(@NonNull Identity identity,
                        @Nullable byte[] passphrase)
            throws GeneralSecurityException, IOException;
}
