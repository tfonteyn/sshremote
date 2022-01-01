package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.transport.PacketIO;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252">
 * RFC 4252 SSH Authentication Protocol </a>
 */
public interface UserAuth {

    /** Service name to request authentication. */
    String SSH_USERAUTH = "ssh-userauth";

    /** Service name to connect/authenticate. */
    String SSH_CONNECTION = "ssh-connection";

    void init(@NonNull SshClientConfig config,
              @NonNull String username,
              @Nullable UserInfo userinfo)
            throws NoSuchAlgorithmException;

    /**
     * Will be called by the Session to do the authentication.
     * Subclasses will implement this method and do the actual
     * authentication, using the {@link PacketIO}'s read/write methods.
     *
     * @param password as set on the session, which might be {@code null}.
     *
     * @return {@code true} if the authentication was successful, else {@code false}.
     *
     * @throws SshPartialAuthException        if the authentication was partially
     *                                        successful, i.e. not yet sufficient to login,
     *                                        but enough to continue with more methods.
     * @throws SshAuthCancelException         if the authentication was deliberately cancelled
     * @throws SshTooManyAuthAttemptException if a method was tried to many times
     * @throws IOException                    on communication with the server problems
     */
    boolean authenticate(@NonNull Session session,
                         @NonNull PacketIO io,
                         @Nullable byte[] password)
            throws IOException, GeneralSecurityException, SshAuthException;
}
