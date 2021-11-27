/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.proxy;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SocketFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A {@link Proxy} implementation using a HTTP proxy.
 * <p>
 * This uses the HTTP CONNECT method as described in Sections 5.2 and 5.3 of RFC 2817.
 * <p>
 * This class only supports Basic Authentication as defined in RFC 2617,
 * i.e. sending user name and password in plaintext. (Both will be
 * encoded using first UTF-8 and then Base64.)
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-luotonen-web-proxy-tunneling-01">
 * Internet Draft <em>Tunneling TCP based protocols through Web proxy
 * servers</em> (Ari Luotonen, expired 1999)</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2817#section-5">
 * RFC 2817 HTTP Upgrade to TLS, Section 5. Upgrade across Proxies</a>
 */
public class ProxyHTTP
        extends ProxyBase {

    private static final int DEFAULT_PORT = 80;

    /**
     * Creates a new ProxyHTTP object.
     *
     * @param proxyHost the proxy's host name, maybe including the port
     *                  number separated by {@code :}. (The default port is 80.)
     */
    public ProxyHTTP(@NonNull final String proxyHost) {
        super(DEFAULT_PORT, proxyHost);
    }

    /**
     * Creates a new ProxyHTTP object.
     *
     * @param proxyHost the proxy's host name.
     * @param proxyPort the port number of the proxy.
     */
    public ProxyHTTP(@NonNull final String proxyHost,
                     final int proxyPort) {
        super(proxyHost, proxyPort);
    }

    /**
     * returns the default proxy port - this is 80 as defined for HTTP.
     */
    public static int getDefaultPort() {
        return DEFAULT_PORT;
    }

    @Override
    public void connect(@NonNull final String host,
                        final int port,
                        final int timeout,
                        @NonNull final SocketFactory socketFactory)
            throws SshProxyException, IOException {
        try {
            initIO(socketFactory, timeout);

            //noinspection ConstantConditions
            out.write(("CONNECT " + host + ":" + port + " HTTP/1.0\r\n")
                    .getBytes(StandardCharsets.UTF_8));

            if (user != null && passwd != null) {
                final Base64.Encoder encoder = Base64.getEncoder();
                out.write(("Proxy-Authorization: Basic " + user + ":")
                        .getBytes(StandardCharsets.UTF_8));
                out.write(encoder.encode(passwd));
                out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            }

            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            int c = 0;

            final StringBuilder sb = new StringBuilder();
            while (c >= 0) {
                //noinspection ConstantConditions
                c = in.read();
                if (c == 13) {
                    c = in.read();
                    if (c == 10) {
                        break;
                    }
                } else {
                    sb.append((char) c);
                }
            }

            if (c < 0) {
                close();
                throw new IOException();
            }

            final String response = sb.toString();
            String reason = "Unknown reason";
            int code = -1;
            try {
                c = response.indexOf(' ');
                final int space = response.indexOf(' ', c + 1);
                code = Integer.parseInt(response.substring(c + 1, space));
                reason = response.substring(space + 1);
            } catch (final Exception ignore) {
            }

            if (code != 200) {
                close();
                throw new IOException("proxy error: " + reason);
            }

            int count;
            do {
                count = 0;
                while (c >= 0) {
                    c = in.read();
                    if (c == 13) {
                        c = in.read();
                        if (c == 10) {
                            break;
                        }
                    } else {
                        count++;
                    }
                }
                if (c < 0) {
                    close();
                    throw new IOException();
                }
            } while (count != 0);

        } catch (final IOException e) {
            close();
            throw e;
        } catch (final Exception e) {
            close();
            throw new SshProxyException("ProxyHTTP", e);
        }
    }
}
