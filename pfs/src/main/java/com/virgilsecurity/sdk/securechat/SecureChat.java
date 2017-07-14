/*
 * Copyright (c) 2017, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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
package com.virgilsecurity.sdk.securechat;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.pfs.EphemeralCardValidator;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.pfs.model.response.OtcCountResponse;
import com.virgilsecurity.sdk.securechat.model.InitiationMessage;
import com.virgilsecurity.sdk.securechat.model.InitiatorSessionState;
import com.virgilsecurity.sdk.securechat.model.Message;
import com.virgilsecurity.sdk.securechat.model.ResponderSessionState;
import com.virgilsecurity.sdk.securechat.model.SessionState;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChat {

    private SecureChatContext config;
    private VirgilPFSClient client;

    SecureChatKeyHelper keyHelper;
    SecureChatCardsHelper cardsHelper;
    SecureChatSessionHelper sessionHelper;

    /**
     * Create new instance of {@link SecureChat}.
     * 
     * @param config
     *            the secure chat context.
     */
    public SecureChat(SecureChatContext config) {
        this.config = config;
        this.client = new VirgilPFSClient(config.getContext());
        this.keyHelper = new SecureChatKeyHelper(config.getCrypto(), config.getKeyStorage(),
                config.getMyIdentityCard().getId(), config.getLongTermKeysTtl());
        this.cardsHelper = new SecureChatCardsHelper(config.getCrypto(), config.getMyPrivateKey(), this.client,
                this.config.getDeviceManager(), this.keyHelper);
        this.sessionHelper = new SecureChatSessionHelper(config.getMyIdentityCard().getId(), config.getUserDefaults());
    }

    private SecureSession startNewSession(CardModel recipientCard, RecipientCardsSet cardsSet, byte[] additionalData) {
        String identityCardId = recipientCard.getId();
        byte[] identityPublicKeyData = recipientCard.getSnapshotModel().getPublicKeyData();
        byte[] longTermPublicKeyData = cardsSet.getLongTermCard().getSnapshotModel().getPublicKeyData();

        KeyPair ephKeyPair = this.config.getCrypto().generateKeys();
        PrivateKey ephPrivateKey = ephKeyPair.getPrivateKey();

        String ephKeyName = this.keyHelper.persistEphPrivateKey(ephPrivateKey, identityCardId);

        EphemeralCardValidator validator = new EphemeralCardValidator(this.config.getCrypto());
        validator.addVerifier(identityCardId, identityPublicKeyData);

        if (!validator.validate(cardsSet.getLongTermCard())) {
            throw new VirgilException("Responder LongTerm card validation failed.");
        }

        if (cardsSet.getOneTimeCard() != null) {
            if (!validator.validate(cardsSet.getOneTimeCard())) {
                throw new VirgilException("Responder OneTime card validation failed.");
            }
        }

        SecureSession.CardEntry identityCardEntry = new SecureSession.CardEntry(identityCardId, identityPublicKeyData);
        SecureSession.CardEntry ltCardEntry = new SecureSession.CardEntry(cardsSet.getLongTermCard().getId(),
                longTermPublicKeyData);

        SecureSession.CardEntry otCardEntry = null;
        if (cardsSet.getOneTimeCard() != null) {
            byte[] oneTimePublicKeyData = cardsSet.getOneTimeCard().getSnapshotModel().getPublicKeyData();
            otCardEntry = new SecureSession.CardEntry(cardsSet.getOneTimeCard().getId(), oneTimePublicKeyData);
        }

        Date date = new Date();
        SecureSessionInitiator secureSession = new SecureSessionInitiator(this.config, this.sessionHelper,
                additionalData, this.config.getMyIdentityCard(), ephPrivateKey, ephKeyName, identityCardEntry,
                ltCardEntry, otCardEntry, false, date, this.getSessionExpirationDate(date));

        return secureSession;
    }

    public SecureSession startNewSession(CardModel card, byte[] additionalData) {
        List<RecipientCardsSet> cardsSets = this.client.getRecipientCardsSet(Arrays.asList(card.getId()));
        if (cardsSets.isEmpty()) {
            throw new VirgilException("Error obtaining recipient cards set. Empty set.");
        }

        RecipientCardsSet cardsSet = cardsSets.get(0);
        return this.startNewSession(card, cardsSet, additionalData);
    }

    public SecureSession activeSession(String recipientWithCardId) {
        SessionState sessionState = this.sessionHelper.getSessionState(recipientWithCardId);
        if (sessionState == null) {
            return null;
        }

        SecureSession secureSession = this.recoverSession(this.config.getMyIdentityCard(), sessionState);

        return secureSession;
    }

    private SecureSession recoverSession(CardModel myIdentityCard, SessionState sessionState) {
        if (sessionState instanceof InitiatorSessionState) {
            return this.recoverInitiatorSession(myIdentityCard, (InitiatorSessionState) sessionState);
        } else if (sessionState instanceof ResponderSessionState) {
            return this.recoverResponderSession(myIdentityCard, (ResponderSessionState) sessionState);
        } else {
            throw new VirgilException("Unknown session state.");
        }
    }

    private SecureSession recoverInitiatorSession(CardModel myIdentityCard,
            InitiatorSessionState initiatorSessionState) {
        String ephKeyName = initiatorSessionState.getEphKeyName();
        PrivateKey ephPrivateKey = null;
        try {
            ephPrivateKey = this.keyHelper.getEphPrivateKeyByEntryName(ephKeyName);
        } catch (Exception e) {
            throw new VirgilException("Error getting ephemeral key from storage.");
        }

        SecureSession.CardEntry identityCardEntry = new SecureSession.CardEntry(
                initiatorSessionState.getRecipientCardId(), initiatorSessionState.getRecipientPublicKey());
        SecureSession.CardEntry ltCardEntry = new SecureSession.CardEntry(
                initiatorSessionState.getRecipientLongTermCardId(),
                initiatorSessionState.getRecipientLongTermPublicKey());
        SecureSession.CardEntry otCardEntry = null;
        String recOtId = initiatorSessionState.getRecipientOneTimeCardId();
        byte[] recOtPub = initiatorSessionState.getRecipientOneTimePublicKey();

        if ((!StringUtils.isBlank(recOtId)) && (recOtPub != null) && (recOtPub.length > 0)) {
            otCardEntry = new SecureSession.CardEntry(recOtId, recOtPub);
        }

        byte[] additionalData = initiatorSessionState.getAdditionalData();

        SecureSession secureSession = new SecureSessionInitiator(this.config, this.sessionHelper, additionalData,
                myIdentityCard, ephPrivateKey, ephKeyName, identityCardEntry, ltCardEntry, otCardEntry, true,
                initiatorSessionState.getCreationDate(), initiatorSessionState.getExpirationDate());

        return secureSession;
    }

    private SecureSession recoverResponderSession(CardModel myIdentityCard,
            ResponderSessionState responderSessionState) {
        SecureSession.CardEntry initiatorCardEntry = new SecureSession.CardEntry(
                responderSessionState.getRecipientIdentityCardId(),
                responderSessionState.getRecipientIdentityPublicKey());
        byte[] additionalData = responderSessionState.getAdditionalData();

        SecureSessionResponder secureSession = new SecureSessionResponder(this.config, this.sessionHelper,
                additionalData, this.keyHelper, initiatorCardEntry, responderSessionState.getEphPublicKeyData(),
                responderSessionState.getRecipientLongTermCardId(), responderSessionState.getRecipientOneTimeCardId(),
                responderSessionState.getCreationDate(), responderSessionState.getExpirationDate());

        return secureSession;
    }

    public SecureSession loadUpSession(CardModel card, String message) {
        return loadUpSession(card, message, null);
    }

    public SecureSession loadUpSession(CardModel card, String message, byte[] additionalData) {
        if (SessionStateResolver.isInitiationMessage(message)) {
            InitiationMessage initiationMessage = SecureSession.extractInitiationMessage(message);

            // Added new one time card
            this.cardsHelper.addCards(this.config.getMyIdentityCard(), false, 1);

            SecureSession.CardEntry cardEntry = new SecureSession.CardEntry(card.getId(),
                    card.getSnapshotModel().getPublicKeyData());

            Date date = new Date();
            SecureSessionResponder secureSession = new SecureSessionResponder(this.config, this.sessionHelper,
                    additionalData, this.keyHelper, cardEntry, date, getSessionExpirationDate(date));

            // TODO
            secureSession.decrypt(initiationMessage);

            return secureSession;
        } else {
            Message msg = SecureSession.extractMessage(message);

            byte[] sessionId = msg.getSessionId();

            SessionState sessionState = this.sessionHelper.getSessionState(card.getId());
            if (!Arrays.equals(sessionId, sessionState.getSessionId())) {
                throw new VirgilException("Session not found.");
            }

            SecureSession session = this.recoverSession(this.config.getMyIdentityCard(), sessionState);

            return session;
        }
    }

    private void cleanup() {
        this.sessionHelper.removeOldSessions();
        Set<String> relevantEphKeys = this.sessionHelper.getEphKeys();
        Set<String> relevantLtCards = this.sessionHelper.getLtCards();
        Set<String> relevantOtCards = this.sessionHelper.getOtCards();

        List<String> otKeys = this.keyHelper.getAllOtCardsIds();

        List<String> exhaustedCardsIds = this.client.validateOneTimeCards(this.config.getMyIdentityCard().getId(),
                otKeys);

        Set<String> relOtCards = new HashSet<>(otKeys);
        relOtCards.removeAll(exhaustedCardsIds);
        relOtCards.addAll(relevantOtCards);

        this.keyHelper.removeOldKeys(relevantEphKeys, relevantLtCards, relOtCards);

    }

    public void initialize() {
        this.cleanup();

        // Check ephemeral cards status
        OtcCountResponse status = this.client.getOtcCount(this.config.getMyIdentityCard().getId());

        // Not enough cards, add more
        int numberOfMissingCards = Math.max(this.config.getNumberOfActiveOneTimeCards() - status.getActive(), 0);
        this.addMissingCards(numberOfMissingCards);
    }

    private void addMissingCards(int numberOfMissingCards) {
        boolean addLtCard = !this.keyHelper.hasRelevantLtKey();
        this.cardsHelper.addCards(this.config.getMyIdentityCard(), addLtCard, numberOfMissingCards);
    }

    private Date getSessionExpirationDate(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.SECOND, this.config.getSessionTtl());

        return cal.getTime();
    }

}
