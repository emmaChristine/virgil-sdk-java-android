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
package com.virgilsecurity.secureenclave.model;

import com.virgilsecurity.sdk.crypto.Key;

/**
 * This is common adaptor for {@link java.security.Key}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class KeyAdaptor implements Key {

    private byte[] recipientId;
    private java.security.Key wrapped;

    /**
     * Create new instance of {@link KeyAdaptor}.
     * 
     * @param recipientId
     *            The recipient identifier.
     * @param key
     *            The recipient key.
     */
    public KeyAdaptor(byte[] recipientId, java.security.Key key) {
        this.recipientId = recipientId;
        this.wrapped = key;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Key#getRecipientId()
     */
    @Override
    public byte[] getRecipientId() {
        return recipientId;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.PrivateKey#getValue()
     */
    @Override
    public byte[] getValue() {
        return wrapped.getEncoded();
    }

    /**
     * @return the wrapped key.
     */
    public java.security.Key getWrapped() {
        return this.wrapped;
    }

}
