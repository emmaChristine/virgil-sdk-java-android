/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.sdk.web.model.jwt;

import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.web.contract.AccessToken;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebTokenBody;
import com.virgilsecurity.sdk.web.model.jwt.JsonWebTokenHeader;

public class JsonWebToken implements AccessToken {

    private JsonWebTokenHeader header;
    private JsonWebTokenBody body;
    private byte[] signature;
    private String stringRepresentation;

    public JsonWebToken(JsonWebTokenBody body) {
        this.body = body;
    }

    public JsonWebToken(JsonWebTokenHeader header,
                        JsonWebTokenBody body) {
        this.header = header;
        this.body = body;
    }

    public JsonWebTokenHeader getHeader() {
        return header;
    }

    public JsonWebTokenBody getBody() {
        return body;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override public String stringRepresentation() {
        if (stringRepresentation == null)
            return stringRepresentation = toString();
        else
            return stringRepresentation;
    }

    @Override public String identity() {
        return null;
    }

    public boolean isExpired() {
        return body.isExpired();
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
