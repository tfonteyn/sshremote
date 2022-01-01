package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;

/**
 * Provides a way to prompt the user for {@code keyboard-interactive} authentication.
 * This interface will be implemented by applications in
 * {@link UserInfo} implementations to support {@code keyboard-interactive}
 * authentication as defined in RFC 4256.
 * <p>
 * Additionally, it is used in case of password-based authorization when the
 * server requests a password change.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4256">
 * RFC 4256 Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)</a>
 */
public interface UIKeyboardInteractive
        extends UserInfo {

    /**
     * Retrieves answers from the user to a number of questions.
     *
     * @param destination identifies the user/host pair where we want to login.
     *                    (This was not sent by the remote side).
     * @param name        the name of the request (could be shown in the
     *                    window title). This may be empty.
     * @param instruction an instruction string to be shown to the user.
     *                    This may be empty, and may contain new-lines.
     * @param prompt      a list of prompt strings.
     * @param echo        for each prompt string, whether to show the
     *                    texts typed in ({@code true}) or to mask them ({@code false}).
     *                    This array will have the same length as {@code prompt}.
     *
     * @return the answers as given by the user. This must be an array of
     * same length as {@code prompt}, if the user confirmed.
     * If the user cancels the input, the return value should be {@code null}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4256#section-3.2">
     * RFC 4256, 3.2. Information Requests</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4256#section-3.3">
     * RFC 4256, 3.3. User Interface</a>
     */
    String[] promptKeyboardInteractive(@NonNull String destination,
                                       @NonNull String name,
                                       @NonNull String instruction,
                                       @NonNull String[] prompt,
                                       boolean[] echo);
}
