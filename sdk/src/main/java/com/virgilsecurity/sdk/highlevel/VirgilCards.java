/*
 * Copyright (c) 2016, Virgil Security, Inc.
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
package com.virgilsecurity.sdk.highlevel;

import java.util.ArrayList;

import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * This class represents list of Virgil Cards.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCards extends ArrayList<VirgilCard> {

    private static final long serialVersionUID = -851151724028601817L;

    private VirgilApiContext context;

    /**
     * Create new instance of {@link VirgilCards}.
     * 
     * @param context
     */
    public VirgilCards(VirgilApiContext context) {
        super();
        this.context = context;
    }

    /**
     * Encrypts and signs the specified buffer with data for current collection of {@link VirgilCard} recipients.
     * 
     * @param buffer
     *            The buffer data to be encrypted.
     * @param key
     *            The signer's {@link VirgilKey}.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer signThenEncrypt(VirgilBuffer buffer, VirgilKey key) {
        return key.signThenEncrypt(buffer, this);
    }

    /**
     * Encrypts and signs the specified buffer with data for current collection of {@link VirgilCard} recipients.
     * 
     * @param plaintext
     *            The plaintext to be encrypted.
     * @param key
     *            The signer's {@link VirgilKey}.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer signThenEncrypt(String plaintext, VirgilKey key) {
        return signThenEncrypt(VirgilBuffer.from(plaintext), key);
    }

    /**
     * Encrypts and signs the specified buffer with data for current collection of {@link VirgilCard} recipients.
     * 
     * @param data
     *            The plaintext to be encrypted.
     * @param key
     *            The signer's {@link VirgilKey}.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer signThenEncrypt(byte[] data, VirgilKey key) {
        return signThenEncrypt(VirgilBuffer.from(data), key);
    }

    /**
     * Encrypts the specified buffer data for list of recipients.
     * 
     * @param buffer
     *            The buffer data to be encrypted.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer encrypt(VirgilBuffer buffer) {
        if (buffer == null) {
            throw new NullArgumentException("buffer");
        }

        PublicKey[] publicKeys = new PublicKey[this.size()];
        int i = 0;
        for (VirgilCard card : this) {
            publicKeys[i++] = card.getPublicKey();
        }

        byte[] cipherdata = this.context.getCrypto().encrypt(buffer.getBytes(), publicKeys);
        return VirgilBuffer.from(cipherdata);
    }

    /**
     * Encrypts the specified buffer data for list of recipients.
     * 
     * @param plaintext
     *            The plaintext to be encrypted.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer encrypt(String plaintext) {
        return encrypt(VirgilBuffer.from(plaintext));
    }

    /**
     * Encrypts the specified buffer data for list of recipients.
     * 
     * @param data
     *            The data to be encrypted.
     * @return A new {@link VirgilBuffer} with encrypted data.
     */
    public VirgilBuffer encrypt(byte[] data) {
        return encrypt(VirgilBuffer.from(data));
    }

}
