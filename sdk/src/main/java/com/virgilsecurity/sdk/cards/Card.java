/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.sdk.cards;

import com.virgilsecurity.sdk.client.model.RawCardContent;
import com.virgilsecurity.sdk.client.model.RawSignature;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.*;

public class Card {

    private String identifier;
    private String identity;
    private PublicKey publicKey;
    private String version;
    private Date createdAt;
    private String previousCardId;
    private Card previousCard;
    private List<CardSignature> signatures; // TODO: 1/22/18 add signatures limit up to 8
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
                             rawCardContent.getCreatedAtDate(),
                             rawCardContent.getPreviousCardId(),
                             cardSignatures);

        return card;
    }
}
