package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.crypto.PrivateKey;

import java.util.Dictionary;
import java.util.Map;

public class SignParams {

    /**
     * The signer's card ID.
     */
    public String signerCardId;

    /**
     * The signer's private key.
     */
    public PrivateKey signerPrivateKey;

    /**
     * The signer's type.
     */
    public SignerType signerType;

    /**
     * Gets the custom fields.
     */
    public Map<String, String> extraFields;

    public String getSignerCardId() {
        return signerCardId;
    }

    public void setSignerCardId(String signerCardId) {
        this.signerCardId = signerCardId;
    }

    public PrivateKey getSignerPrivateKey() {
        return signerPrivateKey;
    }

    public void setSignerPrivateKey(PrivateKey signerPrivateKey) {
        this.signerPrivateKey = signerPrivateKey;
    }

    public SignerType getSignerType() {
        return signerType;
    }

    public void setSignerType(SignerType signerType) {
        this.signerType = signerType;
    }

    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    public void setExtraFields(Map<String, String> extraFields) {
        this.extraFields = extraFields;
    }
}
