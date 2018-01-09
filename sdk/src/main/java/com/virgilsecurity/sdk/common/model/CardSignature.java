package com.virgilsecurity.sdk.common.model;

import com.virgilsecurity.sdk.common.SignerType;

import java.util.Map;

public class CardSignature {

    /**
     * The card ID.
     */
    private String signerId;

    /**
     * Gets the type of signer signature.
     */
    private SignerType signerType;

    /**
     * The digital signature
     */
    private byte[] signature;

    /**
     * Extra fields
     */
    private Map<String, String> extraFields;

    public String getSignerId() {
        return signerId;
    }

    public SignerType getSignerType() {
        return signerType;
    }

    public byte[] getSignature() {
        return signature;
    }

    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    void setSignerType(SignerType signerType) {
        this.signerType = signerType;
    }

    void setSignature(byte[] signature) {
        this.signature = signature;
    }

    void setExtraFields(Map<String, String> extraFields) {
        this.extraFields = extraFields;
    }

    public static final class CardSignatureBuilder {
        private String signerCardId;
        private SignerType signerType;
        private byte[] signature;
        private Map<String, String> extraFields;

        public CardSignatureBuilder() {
        }

        public CardSignatureBuilder signerCardId(String signerCardId) {
            this.signerCardId = signerCardId;
            return this;
        }

        public CardSignatureBuilder signerType(SignerType signerType) {
            this.signerType = signerType;
            return this;
        }

        public CardSignatureBuilder signature(byte[] signature) {
            this.signature = signature;
            return this;
        }

        public CardSignatureBuilder extraFields(Map<String, String> extraFields) {
            this.extraFields = extraFields;
            return this;
        }

        public CardSignature build() {
            CardSignature cardSignature = new CardSignature();
            cardSignature.setSignerId(signerCardId);
            cardSignature.setSignerType(signerType);
            cardSignature.setSignature(signature);
            cardSignature.setExtraFields(extraFields);
            return cardSignature;
        }
    }
}
