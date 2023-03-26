package com.hardbacknutter.sshclient.hostconfig;

import androidx.annotation.NonNull;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import com.hardbacknutter.sshclient.utils.Util;

/**
 * @see HostConfig
 * @see HostConfigRepository
 */
public final class HostConfigRepositoryFactory {
    private HostConfigRepositoryFactory() {
    }

    /**
     * Parses the given string containing an OpenSSH configuration,
     * and returns an instance of {@link HostConfigRepository}.
     *
     * @param s string, which includes an OpenSSH's config
     *
     * @return instance
     */
    @NonNull
    public static HostConfigRepository parseOpenSSHConfig(@NonNull final String s)
            throws IOException {
        try (final Reader r = new StringReader(s)) {
            return new OpenSSHHostConfigRepository(r);
        }
    }

    /**
     * Parses the given file with an OpenSSH configuration,
     * and returns an instance of {@link HostConfigRepository}.
     *
     * @param filename OpenSSH's config file
     *
     * @return instance
     */
    @NonNull
    public static HostConfigRepository parseOpenSSHConfigFile(@NonNull final String filename)
            throws IOException {
        //TODO: Android API 26 limitation
        // try (final Reader r = new FileReader(Util.checkTilde(filename),
        //                                      StandardCharsets.UTF_8)) {
        //noinspection ImplicitDefaultCharsetUsage
        try (final Reader r = new FileReader(Util.checkTilde(filename))) {
            return new OpenSSHHostConfigRepository(r);
        }
    }
}
