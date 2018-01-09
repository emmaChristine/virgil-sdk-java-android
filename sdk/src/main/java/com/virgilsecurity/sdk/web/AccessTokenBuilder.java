package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebToken;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebTokenBody;

import java.util.HashMap;

public class AccessTokenBuilder {

    public String accountId;

    public String appId;

    public TimeSpan lifeTime;

    private JsonWebTokenSignatureGenerator jwtSignatureGenerator;

    public AccessTokenBuilder(String accountId,
                              String appId,
                              TimeSpan lifeTime,
                              PrivateKey apiKey,
                              Crypto crypto) {
        this.accountId = accountId;
        this.appId = appId;
        this.lifeTime = lifeTime;

        jwtSignatureGenerator = new JsonWebTokenSignatureGenerator(crypto, apiKey);
    }

    public String create(String identity, HashMap<String, String> data) {
        JsonWebTokenBody jwtBody = new JsonWebTokenBody(accountId,
                                                        new String[]{appId},
                                                        identity,
                                                        lifeTime,
                                                        "1.0",
                                                        data);
        JsonWebToken jsonWebToken = new JsonWebToken(jwtBody, jwtSignatureGenerator);
        return jsonWebToken.toString();
    }

    public String getAccountId() {
        return accountId;
    }

    public String getAppId() {
        return appId;
    }

    public TimeSpan getLifeTime() {
        return lifeTime;
    }

    public JsonWebTokenSignatureGenerator getJwtSignatureGenerator() {
        return jwtSignatureGenerator;
    }

    public void setJwtSignatureGenerator(JsonWebTokenSignatureGenerator jwtSignatureGenerator) {
        jwtSignatureGenerator = jwtSignatureGenerator;
    }
}
