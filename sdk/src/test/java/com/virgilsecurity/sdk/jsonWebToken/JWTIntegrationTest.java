package com.virgilsecurity.sdk.jsonWebToken;

import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.Crypto;

public class JWTIntegrationTest extends PropertyManager {

    private Crypto crypto;

//    @Before
//    public void setUp() {
//        crypto = new VirgilCrypto();
//    }
//    @Test
//    public CardManager getCardManager(String getIdentity) throws CryptoException {
//        PrivateKey apiPrivateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(API_PRIVATE_KEY));
//
//        HashMap<String, String> data = new HashMap<>();
//        data.put("username", "my username");
//
//        AccessTokenBuilder tokenBuilder = new AccessTokenBuilder(ACCOUNT_ID,
//                                                                 APP_CARD_ID,
//                                                                 TimeSpan.fromTime(10, TimeUnit.MINUTES),
//                                                                 apiPrivateKey,
//                                                                 crypto);
//        String jwt = tokenBuilder.create(getIdentity, data);
//    }
}