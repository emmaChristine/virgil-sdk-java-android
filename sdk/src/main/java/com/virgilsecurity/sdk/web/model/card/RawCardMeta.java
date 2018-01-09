package com.virgilsecurity.sdk.web.model.card;

import com.google.gson.annotations.SerializedName;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class RawCardMeta {

    @SerializedName("signs")
    private Map<String, byte[]> signatures;

    @SerializedName("created_at")
    private Date createdAt;

    @SerializedName("card_version")
    private String version;

    public Map<String, byte[]> getSignatures() {
        return signatures;
    }

    public void setSignatures(Map<String, byte[]> signatures) {
        this.signatures = signatures;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }
}
