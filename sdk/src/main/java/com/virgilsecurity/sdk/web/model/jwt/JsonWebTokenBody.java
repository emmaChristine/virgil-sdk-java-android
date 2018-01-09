package com.virgilsecurity.sdk.web.model.jwt;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.web.TimeSpan;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JsonWebTokenBody {

    @SerializedName("accid")
    private String accountId;

    @SerializedName("appids")
    private String[] appIds;

    @SerializedName("iat")
    private Date createdAt;

    @SerializedName("id")
    private String identity;

    @SerializedName("exp")
    private TimeSpan expireAt;

    @SerializedName("ver")
    private String version;

    @SerializedName("data")
    private Map<String, String> data;

    public JsonWebTokenBody(String accountId,
                            String[] appIds,
                            String identity,
                            TimeSpan lifeTime,
                            String version,
                            Map<String, String> data) {
        this.accountId = accountId;
        this.appIds = appIds;
        this.createdAt = new Date();
        this.identity = identity;
        this.expireAt = lifeTime;
        this.version = version;
        this.data = data;
    }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    public String[] getAppIds() {
        return appIds;
    }

    public void setAppIds(String[] appIds) {
        this.appIds = appIds;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public TimeSpan getExpireAt() {
        return expireAt;
    }

    public void setExpireAt(TimeSpan lifeTime) {
        this.expireAt = lifeTime;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Map<String, String> getData() {
        return data;
    }

    public void setData(Map<String, String> data) {
        this.data = data;
    }

    public boolean isExpired() {
        return new Date().after(expireAt.getExpireDate());
    }
}
