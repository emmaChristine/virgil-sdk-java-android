/*
 * Copyright (c) 2017, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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
package com.virgilsecurity.sdk.client.model.auth;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class GetChallengeMessageRequestModel {

    @SerializedName("resource_owner_virgil_card_id")
    private String cardId;

    /**
     * Create new instance of {@link GetChallengeMessageRequestModel}.
     */
    public GetChallengeMessageRequestModel() {
    }

    /**
     * Create new instance of {@link GetChallengeMessageRequestModel}.
     * 
     * @param cardId
     *            the resource owner VIRGIL Card identifier.
     */
    public GetChallengeMessageRequestModel(String cardId) {
        super();
        this.cardId = cardId;
    }

    /**
     * Gets the resource owner VIRGIL Card identifier.
     * 
     * @return the resource owner VIRGIL Card identifier.
     */
    public String getCardId() {
        return cardId;
    }

    /**
     * Sets the resource owner VIRGIL Card identifier.
     * 
     * @param cardId
     *            the resource owner VIRGIL Card identifier.
     */
    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

}
