package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Session;

/**
 * Allows user interaction.
 * <p>
 * The application can provide an implementation of this interface to
 * {@link Session#setUserInfo} to allow for feedback to the user and retrieving
 * information (e.g. passwords, passphrases or a confirmation) from the user.
 * <p>
 * An extended version of this interface is {@link UIKeyboardInteractive}
 * which allows keyboard-interactive authentication as described in RFC 4256.
 *
 * @see Session#setUserInfo
 * @see UIKeyboardInteractive
 */
public interface UserInfo {

    int RC_GENERIC = 0;
    int RC_CREATE_FILE = 1;
    int RC_CREATE_DIRECTORY = 2;
    int RC_REPLACE_KEY = 3;
    int RC_ACCEPT_NON_MATCHING_KEY = 4;

    /**
     * Shows an informational message to the user.
     *
     * @param message the message to show to the user.
     */
    default void showMessage(@NonNull final String message) {

    }

    /**
     * Prompts the user for a password used for authentication with the remote server.
     *
     * @param message     the default "Password for %s"
     * @param destination user/host
     *
     * @return {@code true} if the user entered a password. This password will
     * then be retrieved by {@link #getPassword}.
     */
    default boolean promptPassword(@NonNull final String message,
                                   @NonNull final String destination) {
        return false;
    }

    /**
     * Returns the password entered by the user.
     * This is called internally after a successful {@link #promptPassword}.
     * <p>
     * Implementations need to return "thePassword".getBytes(StandardCharsets.UTF_8)
     */
    @Nullable
    default byte[] getPassword() {
        return null;
    }

    /**
     * Prompts the user for a passphrase for a public key.
     *
     * @param message     the default "Passphrase for %s"
     * @param destination user/host
     *
     * @return {@code true} if the user entered a passphrase. This password will
     * then be retrieved by {@link #getPassphrase}.
     */
    default boolean promptPassphrase(@NonNull final String message,
                                     @NonNull final String destination) {
        return false;
    }

    /**
     * Returns the passphrase entered by the user.
     * This is called internally after a successful {@link #promptPassphrase}.
     * <p>
     * Implementations need to return "thePassword".getBytes(StandardCharsets.UTF_8)
     */
    @Nullable
    default byte[] getPassphrase() {
        return null;
    }

    /**
     * Prompts the user to answer a yes-no-question.
     * <p>
     * Note: These are currently used to decide whether to create non-existing
     * files or directories, whether to replace an existing host key,
     * and whether to connect despite a non-matching key.
     * </p>
     *
     * @param reasonCode one of the {@link #RC_GENERIC} etc... codes
     *                   Can be used to automate answering, or overriding the message
     * @param message    the prompt message to be shown to the user.
     *
     * @return {@code true} if the user answered with "Yes", else {@code false}.
     */
    default boolean promptYesNo(final int reasonCode,
                                @NonNull final String message) {
        return false;
    }
}
