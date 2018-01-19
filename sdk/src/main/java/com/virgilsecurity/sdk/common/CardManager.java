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

package com.virgilsecurity.sdk.common;

import com.sun.istack.internal.NotNull;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.CardValidationException;
import com.virgilsecurity.sdk.client.model.cards.CardModel;
import com.virgilsecurity.sdk.common.contract.CardVerifier;
import com.virgilsecurity.sdk.common.model.Card;
import com.virgilsecurity.sdk.common.model.RawCardContent;
import com.virgilsecurity.sdk.common.model.RawSignature;
import com.virgilsecurity.sdk.common.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.web.contract.AccessToken;
import com.virgilsecurity.sdk.web.contract.AccessTokenProvider;

import java.util.*;

public class CardManager {
    private static final String CURRENT_CARD_VERSION = "5.0";

    private ModelSigner modelSigner;
    private CardCrypto crypto;
    private AccessTokenProvider accessTokenProvider;
    private CardVerifier cardVerifier;
    private CardClient cardClient;
    private SignCallback signCallback;

    public CardManager(CardCrypto crypto,
                       AccessTokenProvider accessTokenProvider,
                       CardVerifier cardVerifier,
                       CardClient cardClient,
                       SignCallback signCallback) {
        this.crypto = crypto;
        this.accessTokenProvider = accessTokenProvider;
        this.cardVerifier = cardVerifier;
        this.cardClient = cardClient;
        this.signCallback = signCallback;

        this.modelSigner = new ModelSigner(crypto);
    }

    public CardManager(@NotNull ModelSigner modelSigner,
                       @NotNull CardCrypto crypto,
                       @NotNull AccessTokenProvider accessTokenProvider,
                       @NotNull CardVerifier cardVerifier,
                       @NotNull CardClient cardClient,
                       @NotNull SignCallback signCallback) {
        this.modelSigner = modelSigner;
        this.crypto = crypto;
        this.accessTokenProvider = accessTokenProvider;
        this.cardVerifier = cardVerifier;
        this.cardClient = cardClient;
        this.signCallback = signCallback;
    }

    private void verifyCard(Card card) throws VerificationException {
        if (!cardVerifier.verifyCard(card))
            throw new VerificationException();
    }

    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey, String previousCardId) {
        AccessToken token = accessTokenProvider.getToken(false);
        RawCardContent cardContent = new RawCardContent(token.getIdentity(),
                                                        crypto.exportPublicKey(publicKey),
                                                        CURRENT_CARD_VERSION,
                                                        new Date(),
                                                        previousCardId);

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel rawCard = new RawSignedModel(snapshot);
        modelSigner.selfSign(rawCard, privateKey);

        rawCard = signCallback.onSign(rawCard);

        return rawCard;
    }

    public RawSignedModel generateRawCard(PrivateKey privateKey, PublicKey publicKey) {
        AccessToken token = accessTokenProvider.getToken(false);
        RawCardContent cardContent = new RawCardContent(token.getIdentity(),
                                                        crypto.exportPublicKey(publicKey),
                                                        CURRENT_CARD_VERSION,
                                                        new Date());

        byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);
        RawSignedModel cardModel = new RawSignedModel(snapshot, Collections.<RawSignature>emptyList());
        modelSigner.selfSign(cardModel, privateKey);

        cardModel = signCallback.onSign(cardModel);

        return cardModel;
    }

    public Card publishCard(RawSignedModel cardModel) throws VerificationException {
        AccessToken token = accessTokenProvider.getToken(false);
        Card card = Card.parse(crypto,
                               cardClient.publishCard(cardModel, token.toString()));

        verifyCard(card);

        return card;
    }

    public Card publishCard(PrivateKey privateKey,
                            PublicKey publicKey,
                            String previousCardId) throws VerificationException {

        RawSignedModel cardModel = generateRawCard(privateKey, publicKey, previousCardId);

        return publishCard(cardModel);
    }

    public Card publishCard(PrivateKey privateKey, PublicKey publicKey) throws VerificationException {
        RawSignedModel cardModel = generateRawCard(privateKey, publicKey);

        return publishCard(cardModel);
    }

    public Card getCard(String cardId) throws VerificationException {
        AccessToken token = accessTokenProvider.getToken(false);
        Card card = Card.parse(crypto, cardClient.getCard(cardId, token.toString()));

        verifyCard(card);

        return card;
    }

    public List<Card> searchCards(String identity) {
        AccessToken token = accessTokenProvider.getToken(false);

        List<RawSignedModel> cardModels = cardClient.searchCards(identity, token.toString());

        List<Card> cards = new ArrayList<>();
        for (RawSignedModel cardModel : cardModels)
            cards.add(Card.parse(crypto, cardModel));

        return cards;
    }

    public Card importCardBase64(String card) {
        return ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(card), Card.class);
    }

    public Card importCardJson(String card) {
        return ConvertionUtils.deserializeFromJson(card, Card.class);
    }

    public String exportCardAsString(Card card) {
        return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(card));
    }

    public String exportCardAsJson(Card card) {
        return ConvertionUtils.serializeToJson(card);
    }

    public interface SignCallback {
        RawSignedModel onSign(RawSignedModel rawSignedModel);
    }
}
