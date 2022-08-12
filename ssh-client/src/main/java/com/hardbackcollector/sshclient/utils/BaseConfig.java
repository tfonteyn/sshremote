package com.hardbackcollector.sshclient.utils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public interface BaseConfig {

    boolean isValueList(@NonNull String key);

    /**
     * Retrieve the raw String value for an option.
     * Lists will be returned as CSV Strings.
     *
     * @param key      the key for the configuration option
     * @param defValue value to return if the key is not present
     *
     * @return single value: the String value, or {@code defValue} if the key is not present.
     * list value: the CSV String, or {@code defValue} when {@code defValue} is non-{@code null},
     * or {@code ""} when  {@code defValue} is {@code null}.
     */
    @Nullable
    String getString(@NonNull String key,
                     @Nullable String defValue);


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
     * @param key the key for the configuration option
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
     * @param key the key for the configuration option
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
     * <p>
     * If the key is not found, we return an empty {@code List<String>}.
     *
     * @param key the key for the configuration option
     *
     * @return the value corresponding to the key.
     */
    @NonNull
    default List<String> getStringList(@NonNull final String key) {
        return getStringList(key, null);
    }

    @NonNull
    default List<String> getStringList(@NonNull final String key,
                                       @Nullable final String defValue) {
        if (!isValueList(key)) {
            throw new IllegalArgumentException("Key is not a list-value: " + key);
        }
        final String value = getString(key, defValue);
        return value != null ? Arrays.asList(value.split(",")) : new ArrayList<>();
    }
}
