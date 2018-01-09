package com.virgilsecurity.sdk.web.model.card;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class RawCard {

    @SerializedName("content_snapshot")
    private byte[] contentSnapshot;

    @SerializedName("signatures")
    private List<RawCardSignature> signatures;

    @SerializedName("meta")
    private RawCardMeta meta;

    public byte[] getContentSnapshot() {
        return contentSnapshot;
    }

    public void setContentSnapshot(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;
    }

    public List<RawCardSignature> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<RawCardSignature> signatures) {
        this.signatures = signatures;
    }

    public RawCardMeta getMeta() {
        return meta;
    }

    public void setMeta(RawCardMeta meta) {
        this.meta = meta;
    }
}
