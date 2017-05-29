package com.virgilsecurity.secureenclave.exceptions;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

public class MethodNotAllowedException extends CryptoException {

    public MethodNotAllowedException() {
    }

    public MethodNotAllowedException(String message) {
        super(message);
    }
}
