/*
 * Copyright (c) 2016, Virgil Security, Inc.
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

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.virgilsecurity.sdk.client.model.SignableRequestMetaModel;
import com.virgilsecurity.sdk.client.model.SignableRequestModel;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.StringUtils;

/**
 * Base class for requests.
 *
 * @author Andrii Iakovenko
 *
 */
public abstract class SignedRequest {

    protected Type type;
    protected Map<String, byte[]> signatures;
    protected byte[] snapshot;
    // protected String validationToken;

    /**
     * Create a new instance of {@code SignedRequest}
     *
     */
    protected SignedRequest() {
        if (getClass().getGenericSuperclass() instanceof ParameterizedType) {
            this.type = ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        }
        this.signatures = new HashMap<>();
    }

    /**
     * Takes the request snapshot.
     *
     * @return the snapshot.
     */
    public byte[] getSnapshot() {
        if (!isSnapshotTaken()) {
            this.snapshot = this.createSnapshot();
        }

        return this.snapshot;
    }

    protected boolean isSnapshotTaken() {
        return this.snapshot != null && this.snapshot.length > 0;
    }
    
    protected void checkNoSnapshot() {
        if (isSnapshotTaken()) {
            // FIXME
            throw new IllegalArgumentException();
        }
    }

    protected abstract byte[] createSnapshot();

    void sign(Crypto crypto, String id, PrivateKey privateKey) {

        Fingerprint fingerprint = crypto.calculateFingerprint(this.snapshot);
        byte[] signature = crypto.sign(fingerprint.getValue(), privateKey);

        this.signatures.put(id, signature);
    }

    /**
     * Gets the request model.
     * 
     * @return The request model.
     */
    public SignableRequestModel getRequestModel() {
        return this.takeSignableRequestModel();
    }

    SignableRequestModel takeSignableRequestModel() {
        SignableRequestModel requestModel = new SignableRequestModel();
        requestModel.setContentSnapshot(this.getSnapshot());

        SignableRequestMetaModel meta = new SignableRequestMetaModel();
        meta.setSignatures(new HashMap<>(this.getSignatures()));
        requestModel.setMeta(meta);

        // FIXME if (!StringUtils.isBlank(this.validationToken)) {
        // requestModel.getMeta().setValidation(new SignableRequestValidationModel(this.validationToken));
        // }

        return requestModel;
    }

    public void appendSignature(String cardId, byte[] signature) {
        if (StringUtils.isBlank(cardId)) {
            throw new EmptyArgumentException("cardId");
        }

        if (signature == null) {
            throw new NullArgumentException("signature");
        }

        this.signatures.put(cardId, signature);
    }

    /**
     * @return the signatures
     */
    public Map<String, byte[]> getSignatures() {
        return Collections.unmodifiableMap(signatures);
    }

}
