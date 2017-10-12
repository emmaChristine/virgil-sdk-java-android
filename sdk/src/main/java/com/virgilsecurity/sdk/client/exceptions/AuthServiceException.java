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
package com.virgilsecurity.sdk.client.exceptions;

/**
 * @author Andrii Iakovenko
 *
 */
public class AuthServiceException extends VirgilServiceException {

    /**
     * Create new instance of {@link AuthServiceException}.
     */
    public AuthServiceException() {
        super();
    }

    /**
     * Create new instance of {@link AuthServiceException}.
     * 
     * @param cause
     */
    public AuthServiceException(Exception cause) {
        super(cause);
    }

    /**
     * Create new instance of {@link AuthServiceException}.
     * 
     * @param code
     * @param cause
     */
    public AuthServiceException(int code, Exception cause) {
        super(code, cause);
    }

    /**
     * Create new instance of {@link AuthServiceException}.
     * 
     * @param code
     */
    public AuthServiceException(int code) {
        super(code);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.exceptions.VirgilServiceException#getMessageBundleName()
     */
    @Override
    protected String getMessageBundleName() {
        // FIXME auth server message bundle
        return "";
    }

}