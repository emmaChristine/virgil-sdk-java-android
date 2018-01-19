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

package com.virgilsecurity.sdk.common.validation;

import com.virgilsecurity.sdk.common.SignerType;
import com.virgilsecurity.sdk.common.contract.CardVerifier;
import com.virgilsecurity.sdk.common.model.Card;
import com.virgilsecurity.sdk.common.model.CardSignature;
import com.virgilsecurity.sdk.common.model.VerifierCredentials;
import com.virgilsecurity.sdk.common.model.WhiteList;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class VirgilCardVerifier implements CardVerifier {

    private static final String VIRGIL_CARD_ID = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";
    private static final String VIRGIL_PUBLIC_KEY_BASE64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVlSNTAxa1YxdFVuZTJ1T2RrdzRrRXJSUmJKcmMyU3lhejVWMWZ1RytyVnM9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo";

    private CardCrypto crypto;
    private boolean verifySelfSignature = true;
    private boolean verifyVirgilSignature = true;
    private List<WhiteList> whiteLists;

    @Override public boolean verifyCard(Card card) {
        ValidationResult validationResult = new ValidationResult();

        if (verifySelfSignature)
            validate(crypto, card, card.getIdentifier(), card.getPublicKey(), SignerType.SELF, validationResult);

        if (verifyVirgilSignature) {
            byte[] publicKeyData = ConvertionUtils.toBase64Bytes(VIRGIL_PUBLIC_KEY_BASE64);
            PublicKey publicKey = crypto.importPublicKey(publicKeyData);
            if (publicKey == null) {
                validationResult.addError("Error importing VIRGIL Public Key");
            }
            validate(crypto, card, VIRGIL_CARD_ID, publicKey, SignerType.VIRGIL, validationResult);
        }

        boolean containsSignature = false;
        for (WhiteList whiteList : whiteLists) {
            for (VerifierCredentials verifierCredentials : whiteList.getVerifiersCredentials()) {
                for (CardSignature signerId : card.getSignatures()) {
                    if (signerId.getSignerId().equals(verifierCredentials.getId())) {
                        PublicKey publicKey = crypto.importPublicKey(verifierCredentials.getPublicKey());
                        if (publicKey != null)
                            containsSignature = true;
                        else
                            validationResult.addError("Error importing Whitelist Public Key for " + verifierCredentials.getId());
                    }
                }
            }
        }

        if (!containsSignature)
            validationResult.addError("The card does not contain signature from specified Whitelist");

        return validationResult.isValid();
    }

    private void validate(CardCrypto crypto,
                          Card card,
                          String signerCardId,
                          PublicKey signerPublicKey,
                          SignerType signerType,
                          ValidationResult validationResult) {

        if (card.getSignatures() == null || card.getSignatures().isEmpty()) {
            validationResult.addError("The card does not contain any signature");
            return;
        }

        CardSignature signature = card.getSignatures().get(0);
        if (!signature.getSignerId().equals(signerCardId)) {
            validationResult.addError("The card does not contain the " + signerType + " signature");
            return;
        }

        byte[] cardSnapshot = ConvertionUtils.captureSnapshot(card);
        if (cardSnapshot == null) {
            validationResult.addError("The card with id " + signerCardId + " was corrupted");
            return;
        }

        byte[] extraDataSnapshot = new byte[0];
        if (signerType == SignerType.EXTRA) {
            byte[] extraSnapshot = ConvertionUtils.captureSnapshot(signature.getExtraFields());
            if (extraSnapshot == null) {
                validationResult.addError("The EXTRA signature for " + signerCardId + " was corrupted");
                return;
            }
            extraDataSnapshot = extraSnapshot;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write(cardSnapshot);
            outputStream.write(extraDataSnapshot);

        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] fingerprint = crypto.generateSHA256(outputStream.toByteArray());

        if (!crypto.verifySignature(signature.getSignature(), fingerprint, signerPublicKey)) {
            validationResult.addError("The card with id " + signerCardId + " was corrupted");
        }
    }

    public CardCrypto getCardCrypto() {
        return crypto;
    }

    public boolean isIgnoreSelfSignature() {
        return verifySelfSignature;
    }

    public void setIgnoreSelfSignature(boolean ignoreSelfSignature) {
        this.verifySelfSignature = ignoreSelfSignature;
    }

    public boolean isIgnoreVirgilSignature() {
        return verifyVirgilSignature;
    }

    public void setIgnoreVirgilSignature(boolean ignoreVirgilSignature) {
        this.verifyVirgilSignature = ignoreVirgilSignature;
    }

    public List<WhiteList> getWhiteList() {
        return whiteLists;
    }
}
