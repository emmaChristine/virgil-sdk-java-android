/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.crypto;

public class VirgilPBKDF extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    public final static class Algorithm {
        public final static VirgilPBKDF.Algorithm PBKDF2 = new VirgilPBKDF.Algorithm("PBKDF2");

        private static Algorithm[] swigValues = { PBKDF2 };

        private static int swigNext = 0;

        public static Algorithm swigToEnum(int swigValue) {
            if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
                return swigValues[swigValue];
            for (int i = 0; i < swigValues.length; i++)
                if (swigValues[i].swigValue == swigValue)
                    return swigValues[i];
            throw new IllegalArgumentException("No enum " + Algorithm.class + " with value " + swigValue);
        }

        private final int swigValue;

        private final String swigName;

        private Algorithm(String swigName) {
            this.swigName = swigName;
            this.swigValue = swigNext++;
        }

        private Algorithm(String swigName, Algorithm swigEnum) {
            this.swigName = swigName;
            this.swigValue = swigEnum.swigValue;
            swigNext = this.swigValue + 1;
        }
        private Algorithm(String swigName, int swigValue) {
            this.swigName = swigName;
            this.swigValue = swigValue;
            swigNext = swigValue + 1;
        }
        public final int swigValue() {
            return swigValue;
        }
        public String toString() {
            return swigName;
        }
    }

    public final static long kIterationCount_Default = virgil_crypto_javaJNI.VirgilPBKDF_kIterationCount_Default_get();

    protected static long getCPtr(VirgilPBKDF obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    public VirgilPBKDF() {
        this(virgil_crypto_javaJNI.new_VirgilPBKDF__SWIG_0(), true);
    }

    public VirgilPBKDF(byte[] salt) {
        this(virgil_crypto_javaJNI.new_VirgilPBKDF__SWIG_2(salt), true);
    }

    public VirgilPBKDF(byte[] salt, long iterationCount) {
        this(virgil_crypto_javaJNI.new_VirgilPBKDF__SWIG_1(salt, iterationCount), true);
    }

    protected VirgilPBKDF(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilPBKDF_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilPBKDF(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    public byte[] derive(byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilPBKDF_derive__SWIG_1(swigCPtr, this, pwd);
    }

    public byte[] derive(byte[] pwd, long outSize) {
        return virgil_crypto_javaJNI.VirgilPBKDF_derive__SWIG_0(swigCPtr, this, pwd, outSize);
    }

    public void disableRecommendationsCheck() {
        virgil_crypto_javaJNI.VirgilPBKDF_disableRecommendationsCheck(swigCPtr, this);
    }

    public void enableRecommendationsCheck() {
        virgil_crypto_javaJNI.VirgilPBKDF_enableRecommendationsCheck(swigCPtr, this);
    }

    protected void finalize() {
        delete();
    }

    public VirgilPBKDF.Algorithm getAlgorithm() {
        return VirgilPBKDF.Algorithm.swigToEnum(virgil_crypto_javaJNI.VirgilPBKDF_getAlgorithm(swigCPtr, this));
    }

    public VirgilHash.Algorithm getHashAlgorithm() {
        return VirgilHash.Algorithm.swigToEnum(virgil_crypto_javaJNI.VirgilPBKDF_getHashAlgorithm(swigCPtr, this));
    }

    public long getIterationCount() {
        return virgil_crypto_javaJNI.VirgilPBKDF_getIterationCount(swigCPtr, this);
    }

    public byte[] getSalt() {
        return virgil_crypto_javaJNI.VirgilPBKDF_getSalt(swigCPtr, this);
    }

    public void setAlgorithm(VirgilPBKDF.Algorithm alg) {
        virgil_crypto_javaJNI.VirgilPBKDF_setAlgorithm(swigCPtr, this, alg.swigValue());
    }

    public void setHashAlgorithm(VirgilHash.Algorithm hash) {
        virgil_crypto_javaJNI.VirgilPBKDF_setHashAlgorithm(swigCPtr, this, hash.swigValue());
    }

}
