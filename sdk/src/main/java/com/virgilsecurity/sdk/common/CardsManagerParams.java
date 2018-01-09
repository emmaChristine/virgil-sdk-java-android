package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.client.CardValidator;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.web.AccessManager;

import java.util.concurrent.Callable;

public class CardsManagerParams {

    private Crypto crypto;
    private CardValidator validator;
    private Callable<String> signCallable;
    private String apiUrl;
    private AccessManager accessManager;

    public CardsManagerParams()
    {
        validator = new ExtendedValidator();
    }
}
