package com.virgilsecurity.sdk.web.model.jwt;

import com.google.gson.annotations.SerializedName;

public class JsonWebTokenHeader {

    @SerializedName("alg")
    private String algorithm;

    @SerializedName("typ")
    private String type;

    public JsonWebTokenHeader(String algorithm, String type) {
        this.algorithm = algorithm;
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
