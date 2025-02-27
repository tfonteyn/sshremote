package com.hardbacknutter.sshclient;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.Manifest;

import com.hardbacknutter.sshclient.transport.SshClientImpl;
import com.hardbacknutter.sshclient.utils.SshClientConfigImpl;

/**
 * The default configuration can be found in {@link SshClientConfigImpl}
 * in the method {@code loadDefaultConfig()}.
 */
public final class SshClientFactory {

    private static final String VERSION = "1.3.2";
    private static final String META_INF_MANIFEST_MF = "META-INF/MANIFEST.MF";
    private static final String MANIFEST_VERSION = "Manifest-Version";

    private SshClientFactory() {
    }

    /**
     * Get the library version.
     *
     * @return version string
     */
    @NonNull
    public static String getVersionName() {
        // This fails on Android of course.
        final ClassLoader classLoader = SshClientFactory.class.getClassLoader();
        if (classLoader instanceof URLClassLoader) {
            final URL url = ((URLClassLoader) classLoader).findResource(META_INF_MANIFEST_MF);
            try (final InputStream is = url.openStream()) {
                final Manifest manifest = new Manifest(is);
                return manifest.getMainAttributes().getValue(MANIFEST_VERSION);
            } catch (final IOException ignored) {
                // ignored
            }
        }
        // use the fallback for Android.
        return VERSION;
    }

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     *
     * @return new client instance; logging disabled.
     */
    @NonNull
    public static SshClient create() {
        return create(null);
    }

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     *
     * @param logger to use; use {@code null} to disable all logging
     *
     * @return new client instance
     */
    public static SshClient create(@Nullable final Logger logger) {
        return new SshClientImpl(logger);
    }
}
