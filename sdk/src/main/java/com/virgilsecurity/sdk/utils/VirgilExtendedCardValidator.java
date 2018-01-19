package com.virgilsecurity.sdk.utils;

import com.virgilsecurity.sdk.client.ExtendedCardValidator;
import com.virgilsecurity.sdk.client.ValidationResult;
import com.virgilsecurity.sdk.client.model.cards.CardModel;
import com.virgilsecurity.sdk.common.SignerInfo;
import com.virgilsecurity.sdk.common.model.Card;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VirgilExtendedCardValidator implements ExtendedCardValidator {

    private Crypto crypto;

    private List<SignerInfo> whiteList;
    private Map<String, PublicKey> signersCache;
    private boolean ignoreSelfSignature;
    private boolean ignoreVirgilSignature;

    private final static String VIRGIL_CARD_ID = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
    private final static String VIRGIL_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAx"
            + "a1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5E" + "IFBVQkxJQyBLRVktLS0tLQo=";

    public VirgilExtendedCardValidator() {
        whiteList = new ArrayList<>();
        signersCache = new HashMap<>();
    }

    /**
     * Create a new instance of {@code VirgilCardValidator}
     *
     * @param crypto
     *            The crypto instance.
     */
    public VirgilExtendedCardValidator(Crypto crypto) {
        this.crypto = crypto;

        PublicKey servicePublicKey = crypto.importPublicKey(ConvertionUtils.base64ToBytes(VIRGIL_PUBLIC_KEY));

        this.signersCache = new HashMap<>();
        this.signersCache.put(VIRGIL_CARD_ID, servicePublicKey);
    }

    /**
     * Adds the signature verifier.
     *
     * @param verifierId
     *            the verifier identifier.
     * @param verifierPublicKey
     *            the verifier public key.
     */
    public void addVerifier(String verifierId, byte[] verifierPublicKey) {
        if (StringUtils.isBlank(verifierId)) {
            throw new EmptyArgumentException("verifierId");
        }

        if (verifierPublicKey == null) {
            throw new EmptyArgumentException("verifierPublicKey");
        }

        PublicKey publicKey = this.crypto.importPublicKey(verifierPublicKey);
        this.signersCache.put(verifierId, publicKey);
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.client.CardValidator#validate(com.virgilsecurity. sdk.client.model.Card)
     */

    public boolean validate(CardModel card) {
        // Support for legacy Cards.
        if ("3.0".equals(card.getMeta().getVersion())) {
            return true;
        }

        Fingerprint fingerprint = this.crypto.calculateFingerprint(card.getSnapshot());
        String fingerprintHex = fingerprint.toHex();

        if (!fingerprintHex.equals(card.getId())) {
            return false;
        }

        // add self signature verifier
        Map<String, PublicKey> allVerifiers = new HashMap<>(signersCache);
        allVerifiers.put(fingerprintHex, this.crypto.importPublicKey(card.getSnapshotModel().getPublicKeyData()));

        for (Map.Entry<String, PublicKey> verifier : allVerifiers.entrySet()) {

            if (!card.getMeta().getSignatures().containsKey(verifier.getKey())) {
                return false;
            }

            try {
                boolean isValid = this.crypto.verifySignature(fingerprint.getValue(),
                                                              card.getMeta().getSignatures().get(verifier.getKey()), verifier.getValue());

                if (!isValid) {
                    return false;
                }
            } catch (CryptoException e) {
                return false;
            }
        }

        return true;
    }

    @Override public boolean validate(Crypto crypto, CardModel card) {
//        ValidationResult result = new ValidationResult();
//
//        if (ignoreSelfSignature)
//        {
//            ValidateSignerSignature(cardManagerCrypto, card, card.Id, card.PublicKey, "SELF", result);
//        }
//        if (!this.IgnoreVirgilSignature)
//        {
//            var virgilPublicKey = this.GetCachedPublicKey(cardManagerCrypto, VirgilCardId, VirgilPublicKeyBase64);
//            ValidateSignerSignature(cardManagerCrypto, card, VirgilCardId, virgilPublicKey, "VIRGIL", result);
//        }
//        if (!this.whitelist.Any())
//        {
//            return result;
//        }
//
//        // select a first intersected signer from whitelist.
//        var signerCardId = this.whitelist.Select(s => s.CardId)
//                .Intersect(card.Signatures.Select(it => it.SignerCardId)).FirstOrDefault();
//
//        // if signer's signature is not exists in card's collection then this is to be regarded
//        // as a violation of the policy (at least one).
//        if (signerCardId == null)
//        {
//            result.AddError("The card does not contain signature from specified Whitelist");
//        }
//        else
//        {
//            var signerInfo = this.whitelist.Single(s => s.CardId == signerCardId);
//            var signerPublicKey = this.GetCachedPublicKey(cardManagerCrypto, signerCardId, signerInfo.PublicKeyBase64);
//
//            ValidateSignerSignature(cardManagerCrypto, card, signerCardId, signerPublicKey, "Whitelist", result);
//        }
//        return result;
        return false;
    }

    private static void ValidateSignerSignature(Crypto crypto, Card card, String signerCardId,
                                                PublicKey signerPublicKey, String signerKind, ValidationResult result)
    {
//        var signature = card.Signatures.SingleOrDefault(s => s.SignerCardId == signerCardId);
//        if (signature == null)
//        {
//            result.AddError($"The card does not contain the {signerKind} signature");
//            return;
//        }
//
//        // validate verifier's signature
//        if (cardManagerCrypto.VerifySignature(card.Fingerprint, signature.Signature, signerPublicKey))
//        {
//            return;
//        }
//
//        result.AddError($"The {signerKind} signature is not valid");
    }

    public boolean isIgnoreSelfSignature() {
        return ignoreSelfSignature;
    }

    public void setIgnoreSelfSignature(boolean ignoreSelfSignature) {
        this.ignoreSelfSignature = ignoreSelfSignature;
    }

    public boolean isIgnoreVirgilSignature() {
        return ignoreVirgilSignature;
    }

    public void setIgnoreVirgilSignature(boolean ignoreVirgilSignature) {
        this.ignoreVirgilSignature = ignoreVirgilSignature;
    }

    public List<SignerInfo> getWhiteList() {
        return whiteList;
    }

    public void setWhiteList(List<SignerInfo> whiteList) {
        this.whiteList.clear();
        this.signersCache.clear();

        if (whiteList != null)
            this.whiteList.addAll(whiteList);
    }
}
