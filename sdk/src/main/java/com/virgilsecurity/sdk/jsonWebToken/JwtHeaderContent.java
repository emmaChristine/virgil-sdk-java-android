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

package com.virgilsecurity.sdk.jsonWebToken;

import com.google.gson.annotations.SerializedName;

public class JwtHeaderContent {

    @SerializedName("alg")
    private String algorithm;

    @SerializedName("typ")
    private String type;

    @SerializedName("cty")
    private String contentType;

    @SerializedName("kid")
    private String keyIdentifier;

    public JwtHeaderContent() {
    }

    public JwtHeaderContent(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;

        this.algorithm = "VEDS512";
        this.type = "JWT";
        this.contentType = "virgil-jwt;v=1";
    }

    public JwtHeaderContent(String algorithm, String keyIdentifier) {
        this.algorithm = algorithm;
        this.keyIdentifier = keyIdentifier;

        this.type = "JWT";
        this.contentType = "virgil-jwt;v=1";
    }

    public JwtHeaderContent(String algorithm, String type, String keyIdentifier) {
        this.algorithm = algorithm;
        this.type = type;
        this.keyIdentifier = keyIdentifier;

        this.contentType = "virgil-jwt;v=1";
    }

    public JwtHeaderContent(String algorithm, String type, String contentType, String keyIdentifier) {
        this.algorithm = algorithm;
        this.type = type;
        this.contentType = contentType;
        this.keyIdentifier = keyIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getType() {
        return type;
    }

    void setType(String type) {
        this.type = type;
    }

    public String getContentType() {
        return contentType;
    }

    void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
}