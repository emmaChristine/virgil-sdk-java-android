package com.virgilsecurity.secureenclave.exceptions;

import java.io.IOException;

/**
 * Created by teonit on 04.04.17.
 */

public class ASN1Exception extends RuntimeException {

    public ASN1Exception(String message) {
        super(message);
    }

    public ASN1Exception(String message, Throwable cause) {
        super(message, cause);
    }
}
