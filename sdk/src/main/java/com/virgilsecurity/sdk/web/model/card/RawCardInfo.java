package com.virgilsecurity.sdk.web.model.card;

import com.google.gson.annotations.SerializedName;

import java.util.Date;

public class RawCardInfo {

    @SerializedName("identity")
    private String identity;

    @SerializedName("public_key")
    private byte[] publicKeyData;

    @SerializedName("version")
    private String version;

    @SerializedName("created_at")
    private Date createdAt;

    @SerializedName("previous_card_id")
    private String previousCardId;

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public byte[] getPublicKeyData() {
        return publicKeyData;
    }

    public void setPublicKeyData(byte[] publicKeyData) {
        this.publicKeyData = publicKeyData;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getPreviousCardId() {
        return previousCardId;
    }

    public void setPreviousCardId(String previousCardId) {
        this.previousCardId = previousCardId;
    }
}
