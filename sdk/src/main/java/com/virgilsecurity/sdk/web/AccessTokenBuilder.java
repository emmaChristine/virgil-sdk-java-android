package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.web.model.Jwt;
import com.virgilsecurity.sdk.web.model.JwtBodyContent;

import java.util.HashMap;

public class AccessTokenBuilder {

    public String accountId;

    public String appId;

    public TimeSpan lifeTime;

    public AccessTokenBuilder(String accountId,
                              String appId,
                              TimeSpan lifeTime,
                              PrivateKey apiKey,
                              Crypto crypto) {
        this.accountId = accountId;
        this.appId = appId;
        this.lifeTime = lifeTime;
    }

    public String create(String identity, HashMap<String, String> data) {
//        JwtBodyContent jwtBody = new JwtBodyContent(accountId,
//                                                    new String[]{appId},
//                                                    getIdentity,
//                                                    lifeTime,
//                                                    "1.0",
//                                                    data);
//        Jwt jwt = new Jwt(jwtBody, jwtSignatureGenerator);
//        return jwt.toString();
        return null;
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
}
