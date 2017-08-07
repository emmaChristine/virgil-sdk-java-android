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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClient;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.pfs.model.RecipientCardsSet;
import com.virgilsecurity.sdk.securechat.impl.DefaultUserDataStorage;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.storage.DefaultKeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatTest extends BaseIT {

    private static final String USERNAME_IDENTITY_TYPE = "username";
    private Crypto crypto;
    private VirgilClient client;
    private VirgilPFSClient pfsClient;
    private RequestSigner requestSigner;
    private PrivateKey appKey;

    private String aliceIdentity;
    private String bobIdentity;

    private CardModel aliceCard;
    private CardModel bobCard;

    private KeyPair aliceKeys;
    private KeyPair bobKeys;

    private SecureChatContext aliceChatContext;
    private SecureChatContext bobChatContext;

    private SecureChat aliceChat;
    private SecureChat bobChat;

    private int numberOfCards;

    @Before
    public void setUp() throws MalformedURLException {
        // Initialize Crypto
        crypto = new VirgilCrypto();

        // Prepare context
        VirgilPFSClientContext ctx = new VirgilPFSClientContext(APP_TOKEN);

        String url = getPropertyByName("CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("RO_CARDS_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setReadOnlyCardsServiceURL(new URL(url));
        }
        url = getPropertyByName("IDENTITY_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setIdentityServiceURL(new URL(url));
        }
        url = getPropertyByName("EPH_SERVICE");
        if (StringUtils.isNotBlank(url)) {
            ctx.setEphemeralServiceURL(new URL(url));
        }

        this.numberOfCards = 5;

        client = new VirgilClient(ctx);
        pfsClient = new VirgilPFSClient(ctx);
        requestSigner = new RequestSigner(crypto);

        appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);

        // Create alice card
        aliceIdentity = "alice" + UUID.randomUUID().toString();
        bobIdentity = "bob" + UUID.randomUUID().toString();

        aliceKeys = crypto.generateKeys();
        aliceCard = publishCard(aliceIdentity, aliceKeys);

        bobKeys = crypto.generateKeys();
        bobCard = publishCard(bobIdentity, bobKeys);

        aliceChatContext = new SecureChatContext(aliceCard, aliceKeys.getPrivateKey(), crypto, ctx);
        aliceChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), aliceIdentity));
        aliceChatContext.setDeviceManager(new DefaultDeviceManager());
        aliceChatContext.setUserDefaults(new DefaultUserDataStorage());
        aliceChat = new SecureChat(aliceChatContext);

        bobChatContext = new SecureChatContext(bobCard, bobKeys.getPrivateKey(), crypto, ctx);
        bobChatContext.setKeyStorage(new DefaultKeyStorage(System.getProperty("java.io.tmpdir"), bobIdentity));
        bobChatContext.setDeviceManager(new DefaultDeviceManager());
        bobChatContext.setUserDefaults(new DefaultUserDataStorage());
        bobChat = new SecureChat(bobChatContext);
    }

    @Test
    public void aliceToBobFlow() {
        aliceChat.rotateKeys(this.numberOfCards);
        bobChat.rotateKeys(this.numberOfCards);

        SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("No active session yet", aliceSession);

        /** Start new session */
        aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("Security session should be created", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));
        List<CardModel> aliceCards = client.searchCards(SearchCriteria.byIdentity(aliceIdentity));
        assertFalse("Identity card should be created", aliceCards.isEmpty());

        /** Send first message to Bob */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
        List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
        assertFalse("Identity card should be created", bobCards.isEmpty());
        String decryptedFirstMessage = bobSession.decrypt(encryptedFirstMessage);
        assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);

        /** Send second message to Bob */
        String message = UUID.randomUUID().toString();
        aliceSession = aliceChat.activeSession(bobCard.getId());
        String encryptedMessage = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Bob receives message and decrypts it
        bobSession = bobChat.activeSession(aliceCard.getId());
        assertNotNull("Bob session not found", bobSession);
        String decryptedMessage = bobSession.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        /** Send the message to Alice */
        message = UUID.randomUUID().toString();
        encryptedMessage = bobSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Alice receives the message and decrypts it
        aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNotNull("Alice session not found", aliceSession);
        decryptedMessage = aliceSession.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        /** Recover Alice's session */
        aliceChat = new SecureChat(aliceChatContext);
        aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNotNull(aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        // Send message to Bob
        message = UUID.randomUUID().toString();
        encryptedMessage = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Bob receives a message
        bobSession = bobChat.activeSession(aliceCard.getId());
        decryptedMessage = bobSession.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        /** Recover Bob's session */
        bobChat = new SecureChat(bobChatContext);
        bobSession = bobChat.activeSession(aliceCard.getId());
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));

        // Bob decrypts Alice's message
        decryptedMessage = bobSession.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        /** Recover Alices's session by message */
        // Bob sends a message
        message = UUID.randomUUID().toString();
        encryptedMessage = bobSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Alice receives a message
        aliceChat = new SecureChat(aliceChatContext);
        aliceSession = aliceChat.loadUpSession(bobCard, encryptedMessage);
        assertNotNull(aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        /** Recover Bob's session by message */
        // Alice sends a message
        message = UUID.randomUUID().toString();
        encryptedMessage = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Alice receives a message
        bobChat = new SecureChat(bobChatContext);
        bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
        assertNotNull(bobSession);
        assertThat("Alice is initiator", bobSession, instanceOf(SecureSessionResponder.class));

        /** Expire Alices's session. See expire_alice_session */

        /** Expire Bob's session. See expire_bob_session */

        /** Expire long term card. See expire_ltc */

        /** Force weak session */

        /** Start 2 separate responder sessions */

        /** Start 2 separate initiator sessions */

        /** Remove active session */

        /** Recreate removed active session */

        /** Restart invalid session */

        /** Secure chat double initialization */

        /** Secure session time expiration */

        /** Recreate expired session */

        /** Setup session check message type */

        /** Gentle reset */
    }

    @Test
    public void expire_alice_session() throws InterruptedException {
        aliceChatContext.setSessionTtl(10);
        aliceChat.rotateKeys(this.numberOfCards);
        bobChat.rotateKeys(this.numberOfCards);

        SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("No active session yet", aliceSession);

        /** Start new session */
        aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("Security session should be created", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));
        List<CardModel> aliceCards = client.searchCards(SearchCriteria.byIdentity(aliceIdentity));
        assertFalse("Identity card should be created", aliceCards.isEmpty());

        /** Send first message to Bob */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
        List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
        assertFalse("Identity card should be created", bobCards.isEmpty());
        String decryptedFirstMessage = bobSession.decrypt(encryptedFirstMessage);
        assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);

        // Wait until Alice session expire
        long waitTime = aliceSession.getExpirationDate().getTime() - new Date().getTime();
        if (waitTime > 0) {
            Thread.sleep(waitTime + 3000);
        }

        assertTrue("Alice session should be expired at the moment", aliceSession.isExpired());

        /** Send second message to Bob */
        String message = UUID.randomUUID().toString();
        aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("Alice session is expired", aliceSession);
        aliceSession = aliceChat.startNewSession(bobCard, null);
        String encryptedMessage = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Bob receives message and decrypts it
        bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
        assertNotNull("Bob session not found", bobSession);
        String decryptedMessage = bobSession.decrypt(encryptedMessage);
        assertNotNull(decryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);
    }

    @Test
    public void expire_bob_session() throws InterruptedException {
        aliceChat.rotateKeys(this.numberOfCards);
        bobChatContext.setSessionTtl(10);
        bobChat.rotateKeys(this.numberOfCards);

        SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("No active session yet", aliceSession);

        /** Start new session */
        aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("Security session should be created", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));
        List<CardModel> aliceCards = client.searchCards(SearchCriteria.byIdentity(aliceIdentity));
        assertFalse("Identity card should be created", aliceCards.isEmpty());

        /** Send first message to Bob */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
        List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
        assertFalse("Identity card should be created", bobCards.isEmpty());
        String decryptedFirstMessage = bobSession.decrypt(encryptedFirstMessage);
        assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);

        // Wait until Bob's session expire
        long waitTime = bobSession.getExpirationDate().getTime() - new Date().getTime();
        if (waitTime > 0) {
            Thread.sleep(waitTime + 3000);
        }

        assertTrue("Bob session should be expired at the moment", bobSession.isExpired());
        SecureSession outdatedBobSession = bobChat.activeSession(aliceCard.getId());
        assertNull("Not active Bob's session to Alice at the moment", outdatedBobSession);

        bobChat.rotateKeys(numberOfCards);
        // Double rotate helps to check that we removed keys correctly
        bobChat.rotateKeys(numberOfCards);
    }

    @Test
    public void expire_ltc() throws InterruptedException {
        aliceChat.rotateKeys(this.numberOfCards);
        bobChatContext.setSessionTtl(10);
        bobChat.rotateKeys(this.numberOfCards);

        String longTermId1, longTermId2, oneTimeId1, oneTimeId2;

        List<RecipientCardsSet> cardsSet = pfsClient.getRecipientCardsSet(Arrays.asList(bobCard.getId()));
        assertNotNull(cardsSet);
        assertEquals(1, cardsSet.size());

        RecipientCardsSet cardSet = cardsSet.get(0);
        longTermId1 = cardSet.getLongTermCard().getId();
        assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId1));

        oneTimeId1 = cardSet.getOneTimeCard().getId();
        assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(oneTimeId1));

        /** Start new session */
        SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("Security session should be created", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        /** Send first message to Bob */
        String message = UUID.randomUUID().toString();
        String encryptedMessage = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
        List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
        assertFalse("Identity card should be created", bobCards.isEmpty());
        String decryptedMessage = bobSession.decrypt(encryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        // Wait until Bob's session expire
        long waitTime = bobSession.getExpirationDate().getTime() - new Date().getTime();
        if (waitTime > 0) {
            Thread.sleep(waitTime + 3000);
        }

        assertTrue("Bob's session should be expired at the moment", bobSession.isExpired());

        bobChat.rotateKeys(numberOfCards);
        cardsSet = pfsClient.getRecipientCardsSet(bobCard.getId());
        assertNotNull(cardsSet);
        assertEquals(1, cardsSet.size());

        cardSet = cardsSet.get(0);
        longTermId2 = cardSet.getLongTermCard().getId();
        assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId2));

        oneTimeId2 = cardSet.getOneTimeCard().getId();
        assertFalse(com.virgilsecurity.sdk.utils.StringUtils.isBlank(longTermId2));

        assertNotEquals(longTermId1, longTermId2);
        assertNotEquals(oneTimeId1, oneTimeId2);

        message = UUID.randomUUID().toString();
        encryptedMessage = aliceSession.encrypt(message);
        bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage);
        assertNotNull(bobSession);
        decryptedMessage = bobSession.decrypt(encryptedMessage);
    }

    @Test
    public void gentle_reset() throws InterruptedException {
        aliceChatContext.setSessionTtl(10);
        aliceChat.rotateKeys(this.numberOfCards);

        bobChatContext.setSessionTtl(10);
        bobChat.rotateKeys(this.numberOfCards);

        /** Start new session */
        SecureSession aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("Security session should be created", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        /** Send message to Bob */
        String message = UUID.randomUUID().toString();
        String encryptedMessage1 = aliceSession.encrypt(message);
        assertNotNull(encryptedMessage1);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedMessage1));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
        List<CardModel> bobCards = client.searchCards(SearchCriteria.byIdentity(bobIdentity));
        assertFalse("Identity card should be created", bobCards.isEmpty());
        String decryptedMessage = bobSession.decrypt(encryptedMessage1);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        message = UUID.randomUUID().toString();
        String encryptedMessage2 = aliceSession.encrypt(message);
        
        aliceChat.gentleReset();
        aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull(aliceSession);
        
        bobChat.gentleReset();
        
        bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage1);
        assertNull(bobSession);
        
        bobSession = bobChat.loadUpSession(aliceCard, encryptedMessage2);
        assertNull(bobSession);
    }

    private CardModel publishCard(String identity, KeyPair keyPair) {
        byte[] exportedPublicKey = crypto.exportPublicKey(keyPair.getPublicKey());
        PublishCardRequest createCardRequest = new PublishCardRequest(identity, USERNAME_IDENTITY_TYPE,
                exportedPublicKey);
        requestSigner.selfSign(createCardRequest, keyPair.getPrivateKey());
        requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

        return client.publishCard(createCardRequest);
    }

    private void sendMessage(SecureChat chat, CardModel receiverCard, String message) {
        // get an active session by recipient's card id
        SecureSession session = chat.activeSession(receiverCard.getId());

        if (session == null) {
            // start new session with recipient if session wasn't initialized yet
            session = chat.startNewSession(receiverCard, null);
        }

        sendMessage(session, receiverCard, message);
    }

    private void sendMessage(SecureSession session, CardModel receiverCard, String message) {
        String ciphertext = null;
        try {
            // encrypt the message using previously initialized session
            ciphertext = session.encrypt(message);
        } catch (Exception e) {
            // error handling
            return;
        }

        // send a cipher message to recipient using your messaging service
        sendMessageToRecipient(receiverCard.getSnapshotModel().getIdentity(), ciphertext);
    }

    private void sendMessageToRecipient(String identity, String ciphertext) {
        // TODO Auto-generated method stub

    }

    private void receiveMessage(SecureChat chat, CardModel senderCard, String message) {
        try {
            // load an existing session or establish new one
            SecureSession session = chat.loadUpSession(senderCard, message);

            // decrypt message using established session
            String plaintext = session.decrypt(message);

            // handle a message
            handleMessage(plaintext);
        } catch (Exception e) {
            // Error handling
        }
    }

    /**
     * @param plaintext
     */
    private void handleMessage(String plaintext) {
        // TODO Auto-generated method stub

    }

}
