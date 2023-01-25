package com.hardbacknutter.sshclient.hostconfig;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.utils.Globber;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class OpenSSHHostConfig
        implements HostConfig {

    private static final Set<String> KEY_IS_LIST_VALUE = Set.of(
            HostConfig.KEX_ALGS.toLowerCase(Locale.ENGLISH)
            , HostConfig.HOST_KEY_ALGS.toLowerCase(Locale.ENGLISH)
            , HostConfig.CIPHERS.toLowerCase(Locale.ENGLISH)
            , HostConfig.MACS.toLowerCase(Locale.ENGLISH)
            , HostConfig.PREFERRED_AUTHENTICATIONS.toLowerCase(Locale.ENGLISH)
            , HostConfig.PUBLIC_KEY_ACCEPTED_ALGORITHMS.toLowerCase(Locale.ENGLISH)
            , HostConfig.PUBLIC_KEY_ACCEPTED_KEY_TYPES.toLowerCase(Locale.ENGLISH)

            , HostConfig.LOCAL_FORWARD.toLowerCase(Locale.ENGLISH)
            , HostConfig.REMOTE_FORWARD.toLowerCase(Locale.ENGLISH)
    );

    private static final Map<String, String> KEY_MAPPINGS = new HashMap<>();
    private static final Map<String, String> FINGER_PRINTS = new HashMap<>();

    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("[ \t]");

    // Map some our split-client/server settings to the combined OpenSSH keys
    static {
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_CIPHER_STOC, HostConfig.CIPHERS);
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_CIPHER_CTOS, HostConfig.CIPHERS);
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_MAC_CTOS, HostConfig.MACS);
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_MAC_STOC, HostConfig.MACS);
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_COMP_CTOS, HostConfig.COMPRESSION);
        KEY_MAPPINGS.put(KexProposal.PROPOSAL_COMP_STOC, HostConfig.COMPRESSION);
    }

    // Map the OpenSSH syntax to Java syntax.
    static {
        FINGER_PRINTS.put("sha512", "SHA-512");
        FINGER_PRINTS.put("sha384", "SHA-384");
        FINGER_PRINTS.put("sha256", "SHA-256");
        FINGER_PRINTS.put("sha224", "SHA-224");
    }

    private final List<List<String[]>> config = new ArrayList<>();

    @NonNull
    private final String hostOrAlias;

    /**
     * Constructor.
     *
     * @param hostOrAlias the hostname or a hostname alias to lookup the config.
     *                    Can be {@code ""} to retrieve the global configuration.
     * @param repo        the repository keyed to hostOrAlias,
     *                    and a list of options as the values.
     */
    OpenSSHHostConfig(@NonNull final String hostOrAlias,
                      @NonNull final Map<String, List<String[]>> repo) {
        this.hostOrAlias = hostOrAlias;

        // sanity check to see if there are actual entries beside the globals
        if (repo.keySet().size() > 1) {
            repo.forEach((hostKey, hostOptions) -> {
                // skip globals for now
                if (!hostKey.isBlank()) {
                    // Now for each matching "Host" pattern, add the options in-order.
                    Arrays.stream(WHITESPACE_PATTERN.split(hostKey))
                          .map(String::trim)
                          .forEach(hostnamePattern -> {
                              // Patterns within pattern-lists may be negated by preceding
                              // them with an exclamation mark (‘!’)
                              if (hostnamePattern.startsWith("!")) {
                                  if (Globber.globLocalPath(hostnamePattern.substring(1).trim(),
                                                            hostOrAlias)) {
                                      this.config.remove(hostOptions);
                                  } else {
                                      this.config.add(hostOptions);
                                  }
                              } else {
                                  if (Globber.globLocalPath(hostnamePattern, hostOrAlias)) {
                                      this.config.add(hostOptions);
                                  }
                              }
                          });
                }
            });
        }

        // always copy the globals at the END of the list
        final List<String[]> global = repo.get("");
        if (!global.isEmpty()) {
            this.config.add(global);
        }
    }

    @Override
    public boolean isValueList(@NonNull final String key) {
        return KEY_IS_LIST_VALUE.contains(key.toLowerCase(Locale.ENGLISH));
    }

    @Override
    @Nullable
    public String getString(@NonNull final String key,
                            @Nullable final String defValue) {
        // map the key if needed.
        String mappedKey = key;
        if (KEY_MAPPINGS.containsKey(mappedKey)) {
            mappedKey = KEY_MAPPINGS.get(mappedKey);
        }

        final String value;

        if (isValueList(mappedKey)) {
            value = getListOption(mappedKey, defValue);
        } else {
            value = getSingleOption(mappedKey, defValue);
        }

        // transform some specific keys (note: NOT any mapped key!)
        switch (key) {
            case KexProposal.PROPOSAL_COMP_CTOS:
            case KexProposal.PROPOSAL_COMP_STOC: {
                if (value == null || "no".equalsIgnoreCase(value)) {
                    return "none,zlib@openssh.com,zlib";
                }
                return "zlib@openssh.com,zlib,none";
            }

            case HostConfig.FINGERPRINT_HASH: {
                if (value == null || value.isBlank()) {
                    return "SHA-256";
                }
                final String result = FINGER_PRINTS.get(value.toLowerCase(Locale.ENGLISH));
                return result != null ? result : "MD5";
            }

            default:
                return value;
        }
    }

    /**
     * Get a single-value key. We ALWAYS return the first occurrence found.
     *
     * @param key to get
     *
     * @return value
     */
    @Nullable
    private String getSingleOption(@NonNull final String key,
                                   @Nullable final String defValue) {

        // find the first occurrence
        String value;
        for (final List<String[]> v : config) {
            value = v.stream()
                     .filter(kv -> kv[0].equalsIgnoreCase(key))
                     .findFirst()
                     .map(kv -> kv[1])
                     .orElse(null);

            if (value != null) {
                return value;
            }
        }

        return defValue;
    }

    /**
     * Get a value-list for multi-value keys.
     * <p>
     * The values are checked for potential prefixes {@code +}, {@code -} and {@code ^}.
     * <ul>
     *     <li>{@code +} : the specified value will be appended to the default set
     *          instead of replacing them.</li>
     *     <li>{@code -} : the specified value (including wildcards) will be removed
     *          from the default set instead of replacing them.</li>
     *     <li>{@code ^} : the specified value will be placed at the head
     *          of the default set.</li>
     * </ul>
     * The absence of a prefix indicates the default action of {@code +}.
     *
     * @param key      to get
     * @param defValue optional list of defaults.
     *
     * @return list
     */
    @NonNull
    private String getListOption(@NonNull final String key,
                                 @Nullable final String defValue) {

        final List<String> list;

        if (defValue == null || !defValue.contains(",")) {
            list = new ArrayList<>();
        } else {
            list = new ArrayList<>(Arrays.asList(defValue.split(",")));
        }

        for (final List<String[]> v : config) {
            v.stream()
             .filter(kv -> kv[0].equalsIgnoreCase(key))
             .map(kv -> kv[1])
             .filter(Objects::nonNull)
             .map(String::trim)
             .filter(value -> !value.isBlank())
             .forEach(value -> {
                 if (value.startsWith("^")) {
                     list.add(0, value.substring(1));
                 } else if (value.startsWith("-")) {
                     for (final String s : value.substring(1).split(",")) {
                         // remove all occurrences.
                         //noinspection StatementWithEmptyBody
                         while (list.remove(s)) ;
                     }
                 } else if (value.startsWith("+")) {
                     list.add(value.substring(1));
                 } else {
                     list.add(value);
                 }
             });
        }

        // Each element in 'list' can be a csv string on its own.
        // So we join all of them, and split them again.
        final String[] theList = String.join(",", list).split(",");
        // lastly we clean up any duplicates/blanks and return the final CSV string
        return Arrays.stream(theList)
                     .map(String::trim)
                     .filter(s -> !s.isBlank())
                     .distinct()
                     .collect(Collectors.joining(","));
    }

    @Override
    @NonNull
    public String toString() {
        final StringBuilder sb = new StringBuilder("OpenSSHHostConfig=")
                .append(hostOrAlias);
        for (final List<String[]> options : config) {
            sb.append(OpenSSHHostConfigRepository.dbgDump(options));
        }
        return sb.toString();
    }
}
