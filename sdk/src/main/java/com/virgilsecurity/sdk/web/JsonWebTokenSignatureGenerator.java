package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;

public class JsonWebTokenSignatureGenerator {

    private Crypto crypto;
    private PrivateKey privateKey;

    public JsonWebTokenSignatureGenerator(Crypto crypto, PrivateKey privateKey) {
        this.crypto = crypto;
        this.privateKey = privateKey;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
