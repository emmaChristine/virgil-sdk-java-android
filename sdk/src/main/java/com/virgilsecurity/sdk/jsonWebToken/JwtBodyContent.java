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
import com.virgilsecurity.sdk.jsonWebToken.TimeSpan;

import java.util.Date;
import java.util.Map;

public class JwtBodyContent {

    @SerializedName("iss")
    private String appId;

    @SerializedName("sub")
    private String identity;

    @SerializedName("ada")
    private Map<String, String> additionalData;

    @SerializedName("exp")
    private TimeSpan expiresAt;

    @SerializedName("iat")
    private Date issuedAt;

    public JwtBodyContent(String appId,
                          String identity,
                          TimeSpan expiresAt,
                          Date issuedAt) {
        this.appId = appId;
        this.identity = identity;
        this.expiresAt = expiresAt;
        this.issuedAt = issuedAt;
    }

    public JwtBodyContent(String appId,
                          String identity,
                          Map<String, String> additionalData,
                          TimeSpan expiresAt,
                          Date issuedAt) {
        this.appId = appId;
        this.identity = identity;
        this.additionalData = additionalData;
        this.expiresAt = expiresAt;
        this.issuedAt = issuedAt;
    }

    public String getAppId() {
        return appId;
    }

    void setAppId(String appId) {
        this.appId = appId;
    }

    public String getIdentity() {
        return identity;
    }

    void setIdentity(String identity) {
        this.identity = identity;
    }

    public Map<String, String> getAdditionalData() {
        return additionalData;
    }

    void setAdditionalData(Map<String, String> additionalData) {
        this.additionalData = additionalData;
    }

    public TimeSpan getExpiresAt() {
        return expiresAt;
    }

    void setExpiresAt(TimeSpan expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }
}
