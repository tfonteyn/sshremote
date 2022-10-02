package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;

import org.ietf.jgss.MessageProp;

/**
 * Encapsulates a GSS context, i.e. an implementation of the
 * GSS API. This is used by {@link UserAuthGSSAPIWithMIC} to do the
 * actual cryptographic work. (See this class for a description on how this
 * interface is used.)
 * </p>
 * <p>
 * This interface only contains the methods needed for GSS-API authentication,
 * not the full GSS API.
 * </p>
 * <p>
 * An implementation of this interface is included
 * based on the {@linkplain org.ietf.jgss GSS API} included in the
 * Java SE from 1.4 on, using object ID {@code 1.2.840.113554.1.2.2}, i.e.
 * Kerberos v5 as defined in RFC 1964.
 * </p>
 *
 * @see org.ietf.jgss.GSSContext
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2743">
 * RFC 2743 Generic Security Service Application Program Interface Version 2, Update 1</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5653">
 * RFC 5653 Generic Security Service API Version 2: Java Bindings Update</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4462">
 * RFC 4462 Generic Security Service Application Program Interface (GSS-API)
 * Authentication and Key Exchange for the Secure Shell (SSH) Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1964">
 * RFC 1964 The Kerberos Version 5 GSS-API Mechanism</a>
 */
public interface UserAuthGSSContext {

    /**
     * Creates the context.
     *
     * @param user the user name.
     * @param host the server's name.
     *
     * @see org.ietf.jgss.GSSManager#createContext
     */
    void create(@NonNull String user,
                @NonNull String host)
            throws SshAuthException;

    /**
     * Checks is the context establishing already succeeded.
     */
    boolean isEstablished();

    /**
     * Tries to establish the secure context by processing a token
     * from the server and (maybe) creating a new token to send to
     * the server.
     *
     * @param token  an array containing the token received from the server.
     *               At the start, this will be an empty array.
     * @param offset the index in {@code token} where the token actually starts.
     * @param len    the length of the token.
     *
     * @return the token to be sent to the server (if length > 0).
     *
     * @see org.ietf.jgss.GSSContext#initSecContext
     */
    @NonNull
    byte[] init(@NonNull byte[] token,
                int offset,
                int len)
            throws SshAuthException;

    /**
     * Calculates a Message Integrity Code for a message.
     *
     * @param inMsg  an array containing the message for which the
     *               the code should be calculated.
     * @param offset the index in {@code message} where the message actually
     *               starts
     * @param len    the length of the message.
     *
     * @return a token containing the MIC for the message.
     *
     * @see org.ietf.jgss.GSSContext#getMIC(byte[], int, int, MessageProp)
     */
    @NonNull
    byte[] getMIC(@NonNull byte[] inMsg,
                  int offset,
                  int len)
            throws SshAuthException;

    /**
     * Disposes this context, releasing any system resources
     * and stored cryptographic information. The context can't be used
     * after this call.
     */
    void dispose();
}
