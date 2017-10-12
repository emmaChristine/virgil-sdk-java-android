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
package com.virgilsecurity.sdk.client.requests;

import java.util.Map;

import com.virgilsecurity.sdk.client.model.SignableRequestModel;
import com.virgilsecurity.sdk.client.model.cards.CardInfoModel;
import com.virgilsecurity.sdk.client.model.cards.CardScope;
import com.virgilsecurity.sdk.client.model.cards.PublishCardSnapshotModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class CreateCardRequest extends SignedRequest {

    private String identity;
    private byte[] publicKeyData;
    private Map<String, String> customFields;
    protected String identityType;
    protected CardInfoModel info;
    protected CardScope scope;

    /**
     * @return the identity
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * @param identity
     *            the identity to set
     */
    public void setIdentity(String identity) {
        checkNoSnapshot();
        this.identity = identity;
    }

    /**
     * @return the publicKeyData
     */
    public byte[] getPublicKeyData() {
        return publicKeyData;
    }

    /**
     * @param publicKeyData
     *            the publicKeyData to set
     */
    public void setPublicKeyData(byte[] publicKeyData) {
        checkNoSnapshot();
        this.publicKeyData = publicKeyData;
    }

    /**
     * @return the customFields
     */
    public Map<String, String> getCustomFields() {
        return customFields;
    }

    /**
     * @param customFields
     *            the customFields to set
     */
    public void setCustomFields(Map<String, String> customFields) {
        checkNoSnapshot();
        this.customFields = customFields;
    }

    /**
     * @return the info
     */
    public CardInfoModel getInfo() {
        return info;
    }

    /**
     * @param info
     *            the info to set
     */
    public void setInfo(CardInfoModel info) {
        checkNoSnapshot();
        this.info = info;
    }

    /**
     * @return the scope
     */
    public CardScope getScope() {
        return scope;
    }

    /**
     * @param scope
     *            the scope to set
     */
    public void setScope(CardScope scope) {
        this.scope = scope;
    }

    void restoreFromSnapshot(byte[] snapshot) {
        PublishCardSnapshotModel model = SnapshotUtils.parseSnapshot(snapshot, PublishCardSnapshotModel.class);
        this.identity = model.getIdentity();
        this.publicKeyData = model.getPublicKeyData();
        this.customFields = model.getCustomFields();
        this.identityType = model.getIdentityType();
        this.scope = model.getScope();
        this.info = model.getInfo();

        this.snapshot = this.createSnapshot();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.requests.SignedRequest#createSnapshot()
     */
    @Override
    protected byte[] createSnapshot() {
        PublishCardSnapshotModel model = new PublishCardSnapshotModel();
        model.setIdentity(this.identity);
        model.setPublicKeyData(this.publicKeyData);
        model.setCustomFields(this.customFields);
        model.setIdentityType(this.identityType);
        model.setInfo(this.info);
        model.setScope(this.scope);

        return SnapshotUtils.takeSnapshot(model);
    }

    /**
     * Import request.
     * 
     * @param exportedRequest
     *            The request as Base64 encoded string.
     */
    protected void importRequest(String exportedRequest) {
        String jsonModel = ConvertionUtils.base64ToString(exportedRequest);
        SignableRequestModel requestModel = ConvertionUtils.getGson().fromJson(jsonModel, SignableRequestModel.class);

        this.restoreFromSnapshot(requestModel.getContentSnapshot());
        this.signatures = requestModel.getMeta().getSignatures();
    }

    /**
     * Export request.
     * 
     * @return the request model as string.
     */
    public String exportRequest() {
        SignableRequestModel requestModel = this.getRequestModel();

        String json = ConvertionUtils.getGson().toJson(requestModel);
        String base64 = ConvertionUtils.toBase64String(json);
        return base64;
    }

    public void selfSign(Crypto crypto, PrivateKey privateKey) {
        Fingerprint snapshotFingerprint = crypto.calculateFingerprint(this.snapshot);
        this.sign(crypto, snapshotFingerprint.toHex(), privateKey);
    }

}
