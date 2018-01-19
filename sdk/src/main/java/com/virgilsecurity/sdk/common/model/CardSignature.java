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
    private String signerType;

    /**
     * The digital signature
     */
    private byte[] signature;

    /**
     * The digital snapshot
     */
    private byte[] snapshot;

    /**
     * EXTRA fields
     */
    private String extraFields;

    public String getSignerId() {
        return signerId;
    }

    private void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public String getSignerType() {
        return signerType;
    }

    private void setSignerType(String signerType) {
        this.signerType = signerType;
    }

    public byte[] getSignature() {
        return signature;
    }

    private void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getSnapshot() {
        return snapshot;
    }

    private void setSnapshot(byte[] snapshot) {
        this.snapshot = snapshot;
    }

    public String getExtraFields() {
        return extraFields;
    }

    private void setExtraFields(String extraFields) {
        this.extraFields = extraFields;
    }


    public static final class CardSignatureBuilder {
        private String signerId;
        private String signerType;
        private byte[] signature;
        private byte[] snapshot;
        private String extraFields;

        public CardSignatureBuilder() {
        }

        public CardSignatureBuilder signerId(String signerId) {
            this.signerId = signerId;
            return this;
        }

        public CardSignatureBuilder signerType(String signerType) {
            this.signerType = signerType;
            return this;
        }

        public CardSignatureBuilder signature(byte[] signature) {
            this.signature = signature;
            return this;
        }

        public CardSignatureBuilder snapshot(byte[] snapshot) {
            this.snapshot = snapshot;
            return this;
        }

        public CardSignatureBuilder extraFields(String extraFields) {
            this.extraFields = extraFields;
            return this;
        }

        public CardSignature build() {
            CardSignature cardSignature = new CardSignature();
            cardSignature.snapshot = this.snapshot;
            cardSignature.signerType = this.signerType;
            cardSignature.signerId = this.signerId;
            cardSignature.extraFields = this.extraFields;
            cardSignature.signature = this.signature;
            return cardSignature;
        }
    }
}
