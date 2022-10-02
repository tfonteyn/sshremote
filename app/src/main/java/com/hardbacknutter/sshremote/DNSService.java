package com.hardbacknutter.sshremote;

import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Workaround for {@link InetAddress#getByName(String)} which does not support a timeout.
 */
public class DNSService {

    private static final String TAG = "DNSService";

    private final ExecutorService executor;

    public DNSService() {
        executor = Executors.newSingleThreadExecutor(r -> {
            final Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

    @NonNull
    public InetAddress lookup(@NonNull final String host,
                              final long timeoutMs)
            throws IOException,
            SocketTimeoutException,
            UnknownHostException {

        Future<InetAddress> future = null;
        try {
            future = getByName(host);
            final InetAddress inetAddress = future.get(timeoutMs, TimeUnit.MILLISECONDS);
            // sanity check
            if (inetAddress == null) {
                throw new UnknownHostException(host);
            }
            return inetAddress;

        } catch (@NonNull final ExecutionException e) {
            // unwrap if we can
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            // Shouldn't happen... flw...
            if (BuildConfig.DEBUG /* always */) {
                Log.d(TAG, "", e);
            }
            throw new UnknownHostException(host);

        } catch (@NonNull final TimeoutException e) {
            // re-throw as if it's coming from the network call.
            throw new SocketTimeoutException(host);

        } catch (@NonNull final InterruptedException e) {
            // re-throw as if it's coming from the network call.
            throw new UnknownHostException(host);

        } finally {
            if (future != null) {
                future.cancel(true);
            }
        }
    }

    @NonNull
    private Future<InetAddress> getByName(@NonNull final String host) {
        final FutureTask<InetAddress> future = new FutureTask<>(
                () -> InetAddress.getByName(host));
        executor.execute(future);
        return future;
    }
}
