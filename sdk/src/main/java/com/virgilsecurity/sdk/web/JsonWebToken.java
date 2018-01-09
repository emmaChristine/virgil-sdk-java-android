package com.virgilsecurity.sdk.web;

import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebTokenBody;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebTokenHeader;

public class JsonWebToken {

    private JsonWebTokenHeader header;
    private JsonWebTokenBody body;
    private JsonWebTokenSignatureGenerator signatureGenerator;
    private byte[] signature;

    public JsonWebToken(JsonWebTokenBody body, JsonWebTokenSignatureGenerator signatureGenerator) {
        validateSignatureGenerator(signatureGenerator);

        this.body = body;
        this.signatureGenerator = signatureGenerator;
    }

    public JsonWebToken(JsonWebTokenHeader header,
                        JsonWebTokenBody body,
                        JsonWebTokenSignatureGenerator signatureGenerator) {
        this.header = header;
        this.body = body;
        this.signatureGenerator = signatureGenerator;
    }

    public JsonWebTokenHeader getHeader() {
        return header;
    }

    public JsonWebTokenBody getBody() {
        return body;
    }

    public JsonWebTokenSignatureGenerator getSignatureGenerator() {
        return signatureGenerator;
    }

    public byte[] getSignature() {
        return signature;
    }

    private void validateSignatureGenerator(JsonWebTokenSignatureGenerator jwtSignatureGenerator) {
        if (jwtSignatureGenerator == null)
            throw new NullArgumentException("JsonWebTokenSignatureGenerator");

        if (jwtSignatureGenerator.getCrypto() == null)
            throw new NullArgumentException("Crypto");

        if (jwtSignatureGenerator.getPrivateKey() == null)
            throw new NullArgumentException("Private Key");
    }

    private void updateSignature() {
        byte[] unsigned = String.valueOf(this.headerBase64() + "." + this.bodyBase64()).getBytes();
        signature = signatureGenerator.getCrypto().sign(unsigned, signatureGenerator.getPrivateKey());
    }

    public boolean isExpired() {
        return body.isExpired();
    }

    /**
     * Instantiates JsonWebToken object via its String representation
     *
     * @param jwt UTF-8 encoded String
     * @return new JsonWebToken object
     */
    public static JsonWebToken from(String jwt) {
        String[] parts = jwt.split(".");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Wrong JWT format.");
        }

        try {
            JsonWebTokenHeader header = ConvertionUtils.parseSnapshot(parts[0].getBytes(),
                                                                      JsonWebTokenHeader.class);

            JsonWebTokenBody body = ConvertionUtils.parseSnapshot(parts[1].getBytes(),
                                                                  JsonWebTokenBody.class);

            JsonWebTokenSignatureGenerator signature =
                    ConvertionUtils.parseSnapshot(parts[1].getBytes(),
                                                  JsonWebTokenSignatureGenerator.class);
            return new JsonWebToken(header, body, signature);
        } catch (Exception e) {
            throw new IllegalArgumentException("Wrong JWT format.");
        }
    }

    private String headerBase64() {
        return ConvertionUtils.toBase64String(ConvertionUtils.captureSnapshot(header));
    }

    private String bodyBase64() {
        return ConvertionUtils.toBase64String(ConvertionUtils.captureSnapshot(body));
    }

    private String signatureBase64() {
        return ConvertionUtils.toBase64String(signature);
    }

    @Override
    public String toString() {
        return headerBase64() + "." + bodyBase64() + "." + signatureBase64();
    }
}
