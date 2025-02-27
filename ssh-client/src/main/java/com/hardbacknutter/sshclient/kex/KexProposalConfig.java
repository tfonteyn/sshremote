package com.hardbacknutter.sshclient.kex;

import org.jspecify.annotations.NonNull;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;
import com.hardbacknutter.sshclient.signature.SshSignature;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

public class KexProposalConfig {

    @SuppressWarnings("FieldNotUsedInToString")
    private final SshClientConfig config;

    @NonNull
    private final List<String> kexAlgorithms;
    @NonNull
    private final List<String> hostKeyAlgorithms;
    @NonNull
    private final List<String> ciphers_c2s;
    @NonNull
    private final List<String> ciphers_s2c;
    @NonNull
    private final List<String> mac_c2s;
    @NonNull
    private final List<String> mac_s2c;
    @NonNull
    private final List<String> compression_c2s;
    @NonNull
    private final List<String> compression_s2c;
    @NonNull
    private final List<String> language_c2s;
    @NonNull
    private final List<String> language_s2c;

    public KexProposalConfig(@NonNull final SshClientConfig config)
            throws NoSuchAlgorithmException {

        this.config = config;

        // new ArrayList's: we need to be able to modify these
        kexAlgorithms = new ArrayList<>(config.getStringList(HostConfig.KEX_ALGS));
        hostKeyAlgorithms = new ArrayList<>(config.getStringList(HostConfig.HOST_KEY_ALGS));

        ciphers_c2s = config.getStringList(KexProposal.PROPOSAL_CIPHER_CTOS);
        ciphers_s2c = config.getStringList(KexProposal.PROPOSAL_CIPHER_STOC);

        mac_c2s = config.getStringList(KexProposal.PROPOSAL_MAC_CTOS);
        mac_s2c = config.getStringList(KexProposal.PROPOSAL_MAC_STOC);

        compression_c2s = getStringList(config, KexProposal.PROPOSAL_COMP_CTOS,
                                        KexProposal.COMPRESSION_NONE);
        compression_s2c = getStringList(config, KexProposal.PROPOSAL_COMP_STOC,
                                        KexProposal.COMPRESSION_NONE);

        language_c2s = getStringList(config, KexProposal.PROPOSAL_LANG_CTOS, "");
        language_s2c = getStringList(config, KexProposal.PROPOSAL_LANG_STOC, "");

        if (config.getBooleanValue(ImplementationFactory.PK_VALIDATE_ALGORITHM_CLASSES, true)) {
            validate();
        }
    }

    @NonNull
    private static List<String> getStringList(@NonNull final SshClientConfig config,
                                              @NonNull final String key,
                                              @NonNull final String defValue) {
        final List<String> list = config.getStringList(key);
        if (list.isEmpty()) {
            list.add(defValue);
        }
        return list;
    }

    @NonNull
    public List<String> getKexAlgorithms() {
        return new ArrayList<>(kexAlgorithms);
    }

    @NonNull
    public List<String> getHostKeyAlgorithms() {
        return new ArrayList<>(hostKeyAlgorithms);
    }

    @NonNull
    public List<String> getCiphers_c2s() {
        return new ArrayList<>(ciphers_c2s);
    }

    @NonNull
    public List<String> getCiphers_s2c() {
        return new ArrayList<>(ciphers_s2c);
    }

    @NonNull
    public List<String> getMac_c2s() {
        return new ArrayList<>(mac_c2s);
    }

    @NonNull
    public List<String> getMac_s2c() {
        return new ArrayList<>(mac_s2c);
    }

    @NonNull
    public List<String> getCompression_c2s() {
        return new ArrayList<>(compression_c2s);
    }

    @NonNull
    public List<String> getCompression_s2c() {
        return new ArrayList<>(compression_s2c);
    }

    @NonNull
    public List<String> getLanguage_c2s() {
        return new ArrayList<>(language_c2s);
    }

    @NonNull
    public List<String> getLanguage_s2c() {
        return new ArrayList<>(language_s2c);
    }

    private void validate()
            throws NoSuchAlgorithmException {

        validateKexAlgorithms();
        validateServerHostKeyAlgorithms();

        validateAlgorithmPair(ciphers_c2s, ciphers_s2c, KexProposal.CHECK_CIP_ALGS,
                              "cipher", name -> {
                    try {
                        ImplementationFactory.getCipher(config, name);
                        return true;
                    } catch (final NoSuchAlgorithmException e) {
                        return false;
                    }
                });

        validateAlgorithmPair(mac_c2s, mac_s2c, KexProposal.CHECK_MAC_ALGS, "mac", name -> {
            try {
                ImplementationFactory.getMac(config, name);
                return true;
            } catch (final NoSuchAlgorithmException e) {
                return false;
            }
        });
    }

    private void validateKexAlgorithms()
            throws NoSuchAlgorithmException {

        if (kexAlgorithms.isEmpty()) {
            throw new NoSuchAlgorithmException("Kex algorithms not configured");
        }

        // Try to instantiate the class, if that fails, remove the algorithm from the list
        for (final String name : config.getStringList(KexProposal.CHECK_KEX_ALGS)) {
            try {

                final KeyExchange kex = ImplementationFactory.getKeyExchange(config, name);
                kex.initKeyAgreement(config);
            } catch (final GeneralSecurityException e) {
                kexAlgorithms.remove(name);
            }
        }

        if (kexAlgorithms.isEmpty()) {
            throw new NoSuchAlgorithmException("No Kex algorithms available");
        }
    }

    // checkSignatures
    private void validateServerHostKeyAlgorithms()
            throws NoSuchAlgorithmException {

        if (hostKeyAlgorithms.isEmpty()) {
            throw new NoSuchAlgorithmException("HostKey(Signature) algorithms not configured");
        }

        // Try to instantiate the class, if that fails, remove the algorithm from the list
        for (final String name : config.getStringList(KexProposal.CHECK_SIG_ALGS)) {
            try {
                final SshSignature sig = ImplementationFactory.getSignature(config, name);
                sig.init(name);
            } catch (final GeneralSecurityException e) {
                hostKeyAlgorithms.remove(name);
            }
        }

        if (hostKeyAlgorithms.isEmpty()) {
            throw new NoSuchAlgorithmException("No HostKey(Signature) algorithms available");
        }
    }

    private void validateAlgorithmPair(@NonNull final List<String> c2s,
                                       @NonNull final List<String> s2c,
                                       @NonNull final String listToCheck,
                                       @NonNull final String errMsg,
                                       @NonNull final Function<String, Boolean> instantiate)
            throws NoSuchAlgorithmException {

        if (c2s.isEmpty() || s2c.isEmpty()) {
            throw new NoSuchAlgorithmException(errMsg + " algorithms not configured");
        }

        // Try to instantiate the class, if that fails, remove the algorithm from the list
        for (final String name : config.getStringList(listToCheck)) {
            if (s2c.contains(name) || c2s.contains(name)) {
                if (!instantiate.apply(name)) {
                    c2s.remove(name);
                    s2c.remove(name);
                }
            }
        }

        if (c2s.isEmpty() || s2c.isEmpty()) {
            throw new NoSuchAlgorithmException(errMsg + " algorithms: none available");
        }
    }

    @Override
    public String toString() {
        return "KexProposal{"
               + "kexAlgorithms=" + kexAlgorithms
               + ", hostKeyAlgorithms=" + hostKeyAlgorithms
               + ", ciphers_c2s=" + ciphers_c2s
               + ", ciphers_s2c=" + ciphers_s2c
               + ", mac_c2s=" + mac_c2s
               + ", mac_s2c=" + mac_s2c
               + ", compression_c2s=" + compression_c2s
               + ", compression_s2c=" + compression_s2c
               + ", language_c2s=" + language_c2s
               + ", language_s2c=" + language_s2c
               + '}';
    }
}
