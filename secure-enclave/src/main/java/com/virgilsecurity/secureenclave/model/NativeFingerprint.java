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

import com.virgilsecurity.sdk.crypto.Fingerprint;

/**
 * This class implements {@link Fingerprint}.
 * 
 * @author Andrii Iakovenko
 */
public class NativeFingerprint implements Fingerprint {

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    private byte[] value;

    /**
     * Create new instance of {@link NativeFingerprint}.
     *
     * @param fingerprint
     *            the source fingerprint.
     */
    public NativeFingerprint(byte[] fingerprint) {
        this.value = fingerprint;
    }

    /**
     * Create new instance of {@link NativeFingerprint}.
     *
     * @param fingerprintHex
     *            the source fingerprint as hex string.
     */
    public NativeFingerprint(String fingerprintHex) {
        this.value = parseHexBinary(fingerprintHex);

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Fingerprint#getValue()
     */
    @Override
    public byte[] getValue() {
        return this.value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Fingerprint#toHex()
     */
    @Override
    public String toHex() {
        return printHexBinary(this.value);
    }

    /**
     * Convert HEX-string to byte array.
     * 
     * @param hexString
     *            The HEX-string to be converted.
     * @return The byte array.
     */
    public byte[] parseHexBinary(String hexString) {
        final int len = hexString.length();
        // "111" is not a valid hex encoding.
        if (len % 2 != 0) {
            throw new IllegalArgumentException("hexBinary needs to be even-length: " + hexString);
        }

        byte[] out = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int h = hexToBin(hexString.charAt(i));
            int l = hexToBin(hexString.charAt(i + 1));
            if (h == -1 || l == -1) {
                throw new IllegalArgumentException("contains illegal character for hexBinary: " + hexString);
            }

            out[i / 2] = (byte) (h * 16 + l);
        }
        return out;
    }

    /**
     * Convert byte array to HEX-string.
     * 
     * @param data
     *            The byte array to be converted.
     * @return The HEX-string.
     */
    public String printHexBinary(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    private static int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9')
            return ch - '0';
        if ('A' <= ch && ch <= 'F')
            return ch - 'A' + 10;
        if ('a' <= ch && ch <= 'f')
            return ch - 'a' + 10;
        return -1;
    }

}
