package com.virgilsecurity.sdk.common;

public enum SignerType {
    SELF("self"),
    APP("app"),
    EXTRA("extra"),
    VIRGIL("virgil");

    private final String signerType;

    private SignerType(String signerType) {
        this.signerType = signerType;
    }

    public String getRawValue() {
        return signerType;
    }
}
