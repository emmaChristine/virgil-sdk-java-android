package com.virgilsecurity.sdk.web.model.card;

import com.google.gson.annotations.SerializedName;

public class RawCardSignature {

    @SerializedName("signer_id")
    private String signerCardId;

    @SerializedName("signer_type")
    private String signerType;

    @SerializedName("signature")
    private byte[] signature;

    @SerializedName("snapshot")
    private byte[] extraData;

    public String getSignerCardId() {
        return signerCardId;
    }

    public void setSignerCardId(String signerCardId) {
        this.signerCardId = signerCardId;
    }

    public String getSignerType() {
        return signerType;
    }

    public void setSignerType(String signerType) {
        this.signerType = signerType;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getExtraData() {
        return extraData;
    }

    public void setExtraData(byte[] extraData) {
        this.extraData = extraData;
    }
}
