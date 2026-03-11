package com.hardbacknutter.sshclient.utils;

import java.util.Arrays;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * INTERNAL USE ONLY.
 */
public interface BaseConfig {

    /**
     * Check if the given key represents a list-value.
     *
     * @param key to check
     *
     * @return flag
     */
    boolean isValueList(@NonNull String key);

    /**
     * Retrieve the raw String value for an option.
     * Lists will be returned as CSV Strings.
     *
     * @param key      the key for the configuration option
     * @param defValue value to return if the key is not present
     *
     * @return single value: the String value,
     *         or {@code defValue} if the key is not present.
     *         list value: the CSV String,
     *         or {@code defValue} when {@code defValue} is non-{@code null},
     *         or {@code ""} when  {@code defValue} is {@code null}.
     */
    @Nullable
    String getString(@NonNull String key,
                     @Nullable String defValue);

    /**
     * Check if the given key is present and has a value.
     *
     * @param key to check
     *
     * @return {@code true} if there is a non-blank value
     */
    default boolean contains(@NonNull final String key) {
        final String s = getString(key, null);
        return s != null && !s.isBlank();
    }

    /**
     * Convenience method for a single-value {@code String}.
     *
     * @param key the key for the configuration option
     *
     * @return the value, or {@code null} if the key is not present.
     */
    @Nullable
    default String getString(@NonNull final String key) {
        return getString(key, null);
    }

    /**
     * Convenience method for a single-value {@code int}.
     *
     * @param key      the key for the configuration option
     * @param defValue to use if the key is not present
     *
     * @return the value, or {@code defValue} if the key is not present.
     */
    default int getIntValue(@NonNull final String key,
                            final int defValue) {
        final String s = getString(key, null);
        if (s != null) {
            try {
                return Integer.parseInt(s);
            } catch (final NumberFormatException e) {
                // SshClient.getLogger()
                //  .log(Logger.ERROR, () -> "Invalid value for key=" + key + ": " + s);
            }
        }
        return defValue;
    }

    /**
     * Convenience method for a single-value {@code boolean}.
     *
     * @param key      the key for the configuration option
     * @param defValue to use if the key is not present
     *
     * @return the value, or {@code defValue} if the key is not present.
     */
    default boolean getBooleanValue(@NonNull final String key,
                                    final boolean defValue) {
        final String s = getString(key, null);
        if (s != null) {
            return "true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s);
        }
        return defValue;
    }

    /**
     * Convenience method for a multi-value configuration option.
     *
     * @param key the key for the configuration option
     *
     * @return the value corresponding to the key.
     *         Should be treated as an immutable list.
     *         If the key is not found, an empty {@code List<String>}.
     */
    @NonNull
    default List<String> getStringList(@NonNull final String key) {
        return getStringList(key, List.of());
    }

    /**
     * Convenience method for a multi-value configuration option.
     *
     * @param key      the key for the configuration option
     * @param defValue to use if the key is not present
     *
     * @return the value corresponding to the key.
     *         Should be treated as an immutable list.
     *         Can be empty, but never {@code null}.
     */
    @NonNull
    default List<String> getStringList(@NonNull final String key,
                                       @Nullable final List<String> defValue) {
        if (!isValueList(key)) {
            throw new IllegalArgumentException("Key is not a list-value: " + key);
        }
        final String value = getString(key, null);
        if (value != null) {
            return Arrays.asList(value.split(","));
        }
        if (defValue != null) {
            return defValue;
        }
        return List.of();
    }
}
