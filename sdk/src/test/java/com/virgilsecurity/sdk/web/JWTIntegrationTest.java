package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.client.BaseIT;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.highlevel.CardManager;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

public class JWTIntegrationTest extends PropertyManager {

    private Crypto crypto;

    @Before
    public void setUp() {
        crypto = new VirgilCrypto();
    }

    @Test
    private CardManager getCardManager(String identity) throws CryptoException {
        PrivateKey apiPrivateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(API_PRIVATE_KEY));

        HashMap<String, String> data = new HashMap<>();
        data.put("username", "my username");

        AccessTokenBuilder tokenBuilder = new AccessTokenBuilder(ACCOUNT_ID,
                                                                 APP_ID,
                                                                 TimeSpan.fromTime(10, TimeUnit.MINUTES),
                                                                 apiPrivateKey,
                                                                 crypto);
        String jwt = tokenBuilder.create(identity, data);
    }
}
