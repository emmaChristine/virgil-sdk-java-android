package com.virgilsecurity.sdk.common.model;

import com.google.gson.reflect.TypeToken;
import com.virgilsecurity.sdk.common.SignerType;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.web.model.card.RawCard;
import com.virgilsecurity.sdk.web.model.card.RawCardInfo;
import com.virgilsecurity.sdk.web.model.card.RawCardSignature;
import oracle.jvm.hotspot.jfr.StringEncoding;

import java.security.Signer;
import java.util.*;

public class Card {

    private List<CardSignature> signatures;
    private String id;
    private String identity;
    private byte[] fingerprint;
    private PublicKey publicKey;
    private String version;
    private Date createdAt;
    private Card previousCard;
    private String previousCardId;

    public Card(String cardId,
                String identity,
                byte[] fingerprint,
                PublicKey publicKey,
                String version,
                Date createdAt,
                String previousCardId,
                List<CardSignature> signatures) {
        this.id = cardId;
        this.identity = identity;
        this.fingerprint = fingerprint;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.signatures = signatures;
    }

    /**
     * Gets the Card ID that uniquely identifies the Card in Virgil Services.
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the Card ID that uniquely identifies the Card in Virgil Services.
     */
    private void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the identity value that can be anything which identifies the user in your application.
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Sets the identity value that can be anything which identifies the user in your application.
     */
    private void setIdentity(String identity) {
        this.identity = identity;
    }

    /**
     * Gets the fingerprint of the card.
     */
    public byte[] getFingerprint() {
        return fingerprint;
    }

    /**
     * Sets the fingerprint of the card.
     */
    private void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Gets the public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the public key.
     */
    private void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Gets the version of the card.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the version of the card.
     */
    private void setVersion(String version) {
        this.version = version;
    }

    /**
     * Gets the date and time fo card creation in UTC.
     */
    public Date getCreatedAt() {
        return createdAt;
    }

    /**
     * Sets the date and time fo card creation in UTC.
     */
    private void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Get previous Card ID  that current card is used to override to
     */
    public String getPreviousCardId() {
        return previousCardId;
    }

    /**
     * Set previous Card ID  that current card is used to override to
     */
    private void setPreviousCardId(String previousCardId) {
        this.previousCardId = previousCardId;
    }

    /**
     * Get previous Card that current card is used to override to
     */
    public Card getPreviousCard() {
        return previousCard;
    }

    /**
     * Set previous Card that current card is used to override to
     */
    void setPreviousCard(Card previousCard) {
        this.previousCard = previousCard;
    }

    public static Card parse(Crypto crypto, RawCard request) {
        if (request == null) {
            throw new NullArgumentException("request should not be null");
        }

        RawCardInfo requestInfo = ConvertionUtils.parseSnapshot(request.getContentSnapshot(), RawCardInfo.class);
        byte[] fingerprint = crypto.computeHash(request.getContentSnapshot(), HashAlgorithm.SHA256);
        String cardId = ConvertionUtils.toHex(fingerprint);

        List<CardSignature> signatures = new ArrayList<>();
        if (request.getSignatures() != null) {

            for (RawCardSignature rawSignature : request.getSignatures()) {
                CardSignature cardSignature = new CardSignature.CardSignatureBuilder()
                        .signerCardId(rawSignature.getSignerCardId())
                        .signerType(StringUtils.fromStringSignerType(rawSignature.getSignerType()))
                        .signature(rawSignature.getSignature())
                        .extraFields(ConvertionUtils.parseSnapshot(rawSignature.getExtraData(),
                                                                   new TypeToken<Map<String, String>>() {
                                                                   }))
                        .build();
                signatures.add(cardSignature);
            }
        }

        Card card = new Card(cardId,
                             requestInfo.getIdentity(),
                             fingerprint,
                             crypto.importPublicKey(requestInfo.getPublicKeyData()),
                             requestInfo.getVersion(),
                             requestInfo.getCreatedAt(),
                             requestInfo.getPreviousCardId(),
                             signatures);

        return card;
    }

    public static List<Card> parse(Crypto crypto, List<RawCard> requests) {
        if (requests == null) {
            throw new NullArgumentException(nameof(requests));
        }

        List<RawCard> cards = new ArrayList<>();
        for (RawCard rawCard : requests) {
            cards.add(rawCard);
        }

        return requests.Select(r = > parse(crypto, r)).ToList();
    }
}
