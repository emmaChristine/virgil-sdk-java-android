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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.pfs.BaseIT;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.securechat.utils.SessionStateResolver;
import com.virgilsecurity.sdk.storage.VirgilKeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatTest extends BaseIT {

    private static final String USERNAME_IDENTITY_TYPE = "username";
    private Crypto crypto;
    private VirgilClient client;
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

        client = new VirgilClient(ctx);
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
        aliceChatContext.setKeyStorage(new VirgilKeyStorage());
        aliceChatContext.setDeviceManager(new DefaultDeviceManager());
        aliceChatContext.setUserDefaults(new DefaultUserDataStorage());
        aliceChat = new SecureChat(aliceChatContext);

        bobChatContext = new SecureChatContext(bobCard, bobKeys.getPrivateKey(), crypto, ctx);
        bobChatContext.setKeyStorage(new VirgilKeyStorage());
        bobChatContext.setDeviceManager(new DefaultDeviceManager());
        bobChatContext.setUserDefaults(new DefaultUserDataStorage());
        bobChat = new SecureChat(bobChatContext);
    }

    @Test
    public void aliceToBobFlow() {
        aliceChat.initialize();
        bobChat.initialize();

        SecureSession aliceSession = aliceChat.activeSession(bobCard.getId());
        assertNull("No active session yet", aliceSession);

        /** Start new session */
        aliceSession = aliceChat.startNewSession(bobCard, null);
        assertNotNull("New session started", aliceSession);
        assertThat("Alice is initiator", aliceSession, instanceOf(SecureSessionInitiator.class));

        /** Send first message to Bob */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));

        // Bob receives message and create session
        SecureSession bobSession = bobChat.loadUpSession(aliceCard, encryptedFirstMessage);
        assertNotNull(bobSession);
        assertThat("Bob is responder", bobSession, instanceOf(SecureSessionResponder.class));
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

        /** Expire Alices's session */

        /** Expire Bob's session */

        /** Expire long term card */
    }
    
    @Test
    @Ignore
    public void aliceToMyselfFlow() {
        aliceChat.initialize();

        SecureSession aliceInitiatorSession = aliceChat.activeSession(aliceCard.getId());
        assertNull("No active session yet", aliceInitiatorSession);

        /** Start new session */
        aliceInitiatorSession = aliceChat.startNewSession(aliceCard, null);
        assertNotNull("New session started", aliceInitiatorSession);
        assertThat("Alice is initiator", aliceInitiatorSession, instanceOf(SecureSessionInitiator.class));

        /** Send first message to myself */
        String firstMessage = UUID.randomUUID().toString();
        String encryptedFirstMessage = aliceInitiatorSession.encrypt(firstMessage);
        assertNotNull(encryptedFirstMessage);
        assertTrue(SessionStateResolver.isInitiationMessage(encryptedFirstMessage));
        
        /** Alice receives message and create session */
        SecureSession aliceResponserSession = aliceChat.loadUpSession(aliceCard, encryptedFirstMessage);
        assertNotNull(aliceResponserSession);
        assertThat("Alice is responder", aliceResponserSession, instanceOf(SecureSessionResponder.class));
        String decryptedFirstMessage = aliceResponserSession.decrypt(encryptedFirstMessage);
        assertEquals("Message should be decrypted properly", firstMessage, decryptedFirstMessage);
        
        /** Send second message to myself */
        String message = UUID.randomUUID().toString();
        aliceInitiatorSession =  aliceChat.activeSession(aliceCard.getId());
        String encryptedMessage = aliceInitiatorSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));
        
        /** Alice receives second message */
        aliceResponserSession = aliceChat.activeSession(aliceCard.getId());
        assertNotNull(aliceResponserSession);
        assertThat("Alice is responder", aliceResponserSession, instanceOf(SecureSessionResponder.class));
        String decryptedMessage = aliceResponserSession.decrypt(encryptedMessage);
        assertEquals("Message should be decrypted properly", message, decryptedMessage);

        /** Send message to initiator Alice */
        message = UUID.randomUUID().toString();
        encryptedMessage = aliceResponserSession.encrypt(message);
        assertNotNull(encryptedMessage);
        assertFalse(SessionStateResolver.isInitiationMessage(encryptedMessage));
    }

    private CardModel publishCard(String identity, KeyPair keyPair) {
        byte[] exportedPublicKey = crypto.exportPublicKey(keyPair.getPublicKey());
        PublishCardRequest createCardRequest = new PublishCardRequest(identity, USERNAME_IDENTITY_TYPE,
                exportedPublicKey);
        requestSigner.selfSign(createCardRequest, keyPair.getPrivateKey());
        requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

        return client.publishCard(createCardRequest);
    }

}
