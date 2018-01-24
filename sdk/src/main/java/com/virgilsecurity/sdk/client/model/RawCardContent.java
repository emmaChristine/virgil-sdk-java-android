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

package com.virgilsecurity.sdk.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.Date;

public class RawCardContent {

    @SerializedName("getIdentity")
    private String identity;

    @SerializedName("public_key")
    private byte[] publicKeyData;

    @SerializedName("version")
    private String version;

    @SerializedName("created_at")
    private Date createdAt;

    @SerializedName("previous_card_id")
    private String previousCardId;

    public RawCardContent() {

    }

    public RawCardContent(String identity, byte[] publicKeyData, String version, Date createdAt) {
        this.identity = identity;
        this.publicKeyData = publicKeyData;
        this.version = version;
        this.createdAt = createdAt;
    }

    public RawCardContent(String identity,
                          byte[] publicKeyData,
                          String version,
                          Date createdAt,
                          String previousCardId) {
        this.identity = identity;
        this.publicKeyData = publicKeyData;
        this.version = version;
        this.createdAt = createdAt;
        this.previousCardId = previousCardId;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public byte[] getPublicKeyData() {
        return publicKeyData;
    }

    public void setPublicKeyData(byte[] publicKeyData) {
        this.publicKeyData = publicKeyData;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getPreviousCardId() {
        return previousCardId;
    }

    public void setPreviousCardId(String previousCardId) {
        this.previousCardId = previousCardId;
    }
}
