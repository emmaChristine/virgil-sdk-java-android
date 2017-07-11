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

import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.pfs.VirgilPFSClientContext;
import com.virgilsecurity.sdk.storage.KeyStorage;

/**
 * @author Andrii Iakovenko
 *
 */
public class SecureChatContext {

    private CardModel myIdentityCard;
    private PrivateKey myPrivateKey;
    private Crypto crypto;
    private KeyStorage keyStorage;
    private VirgilPFSClientContext context;
    private DeviceManager deviceManager;
    private int numberOfActiveOneTimeCards;

    /* Long term key time to live in seconds */
    private int longTermKeysTtl;

    /* Session time to live in seconds */
    private int sessionTtl;

    /**
     * Create new instance of {@link SecureChatContext}.
     */
    public SecureChatContext() {
        super();
        numberOfActiveOneTimeCards = 100;
        longTermKeysTtl = 24 * 60 * 60; // One day
        sessionTtl = 7 * 24 * 60 * 60; // One week
    }

    /**
     * Create new instance of {@link SecureChatContext}.
     * 
     * @param myIdentityCard
     * @param myPrivateKey
     * @param crypto
     */
    public SecureChatContext(CardModel myIdentityCard, PrivateKey myPrivateKey, Crypto crypto, String accessToken) {
        super();
        this.myIdentityCard = myIdentityCard;
        this.myPrivateKey = myPrivateKey;
        this.crypto = crypto;
        this.context = new VirgilPFSClientContext(accessToken);
    }

    /**
     * @return the myIdentityCard
     */
    public CardModel getMyIdentityCard() {
        return myIdentityCard;
    }

    /**
     * @param myIdentityCard
     *            the myIdentityCard to set
     */
    public void setMyIdentityCard(CardModel myIdentityCard) {
        this.myIdentityCard = myIdentityCard;
    }

    /**
     * @return the myPrivateKey
     */
    public PrivateKey getMyPrivateKey() {
        return myPrivateKey;
    }

    /**
     * @param myPrivateKey
     *            the myPrivateKey to set
     */
    public void setMyPrivateKey(PrivateKey myPrivateKey) {
        this.myPrivateKey = myPrivateKey;
    }

    /**
     * @return the crypto
     */
    public Crypto getCrypto() {
        return crypto;
    }

    /**
     * @param crypto
     *            the crypto to set
     */
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    /**
     * @return the keyStorage
     */
    public KeyStorage getKeyStorage() {
        return keyStorage;
    }

    /**
     * @param keyStorage
     *            the keyStorage to set
     */
    public void setKeyStorage(KeyStorage keyStorage) {
        this.keyStorage = keyStorage;
    }

    /**
     * @return the context
     */
    public VirgilPFSClientContext getContext() {
        return context;
    }

    /**
     * @param context
     *            the context to set
     */
    public void setContext(VirgilPFSClientContext context) {
        this.context = context;
    }

    /**
     * @return the deviceManager
     */
    public DeviceManager getDeviceManager() {
        return deviceManager;
    }

    /**
     * @param deviceManager
     *            the deviceManager to set
     */
    public void setDeviceManager(DeviceManager deviceManager) {
        this.deviceManager = deviceManager;
    }

    /**
     * @return the numberOfActiveOneTimeCards
     */
    public int getNumberOfActiveOneTimeCards() {
        return numberOfActiveOneTimeCards;
    }

    /**
     * @param numberOfActiveOneTimeCards
     *            the numberOfActiveOneTimeCards to set
     */
    public void setNumberOfActiveOneTimeCards(int numberOfActiveOneTimeCards) {
        this.numberOfActiveOneTimeCards = numberOfActiveOneTimeCards;
    }

    /**
     * @return the longTermKeysTtl
     */
    public int getLongTermKeysTtl() {
        return longTermKeysTtl;
    }

    /**
     * @param longTermKeysTtl
     *            the longTermKeysTtl to set
     */
    public void setLongTermKeysTtl(int longTermKeysTtl) {
        this.longTermKeysTtl = longTermKeysTtl;
    }

    /**
     * @return the sessionTtl
     */
    public int getSessionTtl() {
        return sessionTtl;
    }

    /**
     * @param sessionTtl
     *            the sessionTtl to set
     */
    public void setSessionTtl(int sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

}
