package com.hardbackcollector.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SocketFactory;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class SocketFactoryImpl
        implements SocketFactory {

    @Override
    @NonNull
    public Socket createSocket(@NonNull final String host,
                               final int port)
            throws IOException, UnknownHostException {
        return createSocket(host, port, 0);
    }

    @Override
    @NonNull
    public Socket createSocket(@Nullable final String host,
                               final int port,
                               final int timeoutInMillis)
            throws IOException, UnknownHostException {

        if (timeoutInMillis == 0) {
            return new Socket(host, port);
        }

        final Socket[] socket = new Socket[1];
        final Exception[] ee = new Exception[1];

        final Thread tmp = new Thread(() -> {
            socket[0] = null;
            try {
                socket[0] = new Socket(host, port);
            } catch (final Exception e) {
                ee[0] = e;
                if (socket[0] != null && socket[0].isConnected()) {
                    try {
                        socket[0].close();
                    } catch (final Exception ignore) {
                    }
                }
                socket[0] = null;
            }
        });
        tmp.setName("Opening Socket " + host);
        tmp.start();

        String message = "";
        try {
            tmp.join(timeoutInMillis);
            message = "timeout: ";
        } catch (final InterruptedException ignore) {
        }

        if (socket[0] != null && socket[0].isConnected()) {
            return socket[0];

        } else {
            message += "socket is not established";
            if (ee[0] != null) {
                message = ee[0].toString();
            }
            tmp.interrupt();
            if (ee[0] instanceof UnknownHostException) {
                throw (UnknownHostException) ee[0];
            } else if (ee[0] instanceof IOException) {
                throw (IOException) ee[0];
            }
            // in the unlikely event of a runtime exception, just throw it as IO....
            throw new IOException(message, ee[0]);
        }
    }
}
