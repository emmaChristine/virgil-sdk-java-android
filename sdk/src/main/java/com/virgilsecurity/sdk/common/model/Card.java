package com.virgilsecurity.sdk.common.model;

import com.google.gson.reflect.TypeToken;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.util.*;

public class Card {

    private String identifier;
    private String identity;
    private PublicKey publicKey;
    private String version;
    private Date createdAt;
    private String previousCardId;
    private Card previousCard;
    private List<CardSignature> signatures;
    private boolean isOutdated;

    public Card(String identifier,
                String identity,
                PublicKey publicKey,
                String version,
                Date createdAt,
                List<CardSignature> signatures) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.signatures = signatures;
    }

    public Card(String identifier,
                String identity,
                PublicKey publicKey,
                String version,
                Date createdAt,
                String previousCardId, List<CardSignature> signatures) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.signatures = signatures;
    }

    public Card(String identifier,
                String identity,
                PublicKey publicKey,
                String version,
                Date createdAt,
                String previousCardId,
                Card previousCard,
                List<CardSignature> signatures) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.previousCard = previousCard;
        this.signatures = signatures;
    }

    public Card(String identifier,
                String identity,
                PublicKey publicKey,
                String version,
                Date createdAt,
                String previousCardId,
                Card previousCard,
                List<CardSignature> signatures, boolean isOutdated) {
        this.identifier = identifier;
        this.identity = identity;
        this.publicKey = publicKey;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
        this.previousCard = previousCard;
        this.signatures = signatures;
        this.isOutdated = isOutdated;
    }

    public String getIdentifier() {
        return identifier;
    }

    /**
     * Gets the getIdentity value that can be anything which identifies the user in your application.
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Gets the public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Gets the version of the card.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Gets the date and time fo card creation in UTC.
     */
    public Date getCreatedAt() {
        return createdAt;
    }

    /**
     * Get previous Card ID  that current card is used to override to
     */
    public String getPreviousCardId() {
        return previousCardId;
    }

    /**
     * Get previous Card that current card is used to override to
     */
    public Card getPreviousCard() {
        return previousCard;
    }

    public List<CardSignature> getSignatures() {
        return signatures;
    }

    public boolean isOutdated() {
        return isOutdated;
    }

    public static Card parse(CardCrypto crypto, RawSignedModel cardModel) {
        if (cardModel == null)
            throw new NullArgumentException("Card -> 'cardModel' should not be null");

        RawCardContent rawCardContent = ConvertionUtils.parseSnapshot(cardModel.getContentSnapshot(),
                                                                      RawCardContent.class);
        byte[] fingerprint = crypto.generateSHA256(cardModel.getContentSnapshot());
        String cardId = ConvertionUtils.toHex(fingerprint);
        PublicKey publicKey = crypto.importPublicKey(rawCardContent.getPublicKeyData());

        List<CardSignature> cardSignatures = new ArrayList<>();
        if (cardModel.getSignatures() != null) {

            for (RawSignature rawSignature : cardModel.getSignatures()) {
                CardSignature cardSignature = new CardSignature.CardSignatureBuilder()
                        .signerId(rawSignature.getSignerId())
                        .signerType(rawSignature.getSignerType())
                        .signature(rawSignature.getSignature())
                        .snapshot(ConvertionUtils.base64ToBytes(rawSignature.getSnapshot()))
                        .extraFields(ConvertionUtils.base64ToString(rawSignature.getSnapshot()))
                        .build();

                cardSignatures.add(cardSignature);
            }
        }

        Card card = new Card(cardId,
                             rawCardContent.getIdentity(),
                             publicKey,
                             rawCardContent.getVersion(),
                             rawCardContent.getCreatedAt(),
                             rawCardContent.getPreviousCardId(),
                             cardSignatures);

        return card;
    }
}
