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

import com.virgilsecurity.sdk.client.model.RawSignature;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

public class ModelSigner {

    private CardCrypto crypto;

    public ModelSigner(CardCrypto crypto) {
        this.crypto = crypto;
    }

    public void sign(RawSignedModel model,
                     String id, // TODO: 1/15/18 do we need this?
                     SignerType type,
                     byte[] additionalData,
                     PrivateKey privateKey) {

        byte[] combinedSnapshot = new byte[2];
        byte[] fingerprint = crypto.generateSHA256(combinedSnapshot);
        byte[] signature = new byte[0];
        try {
            signature = crypto.generateSignature(fingerprint, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String signerId = ConvertionUtils.toHex(crypto.generateSHA256(model.getContentSnapshot()));

        RawSignature rawSignature = new RawSignature(signerId,
                                                     ConvertionUtils.toHex(additionalData),
                                                     type.getRawValue(),
                                                     signature);

        model.getSignatures().add(rawSignature);
    }

    public void selfSign(RawSignedModel model, byte[] additionalData, PrivateKey privateKey) {
        sign(model, null, SignerType.SELF, additionalData, privateKey);
    }

    public void selfSign(RawSignedModel model, PrivateKey privateKey) {
        sign(model, null, SignerType.SELF, new byte[0], privateKey);
    }
}
