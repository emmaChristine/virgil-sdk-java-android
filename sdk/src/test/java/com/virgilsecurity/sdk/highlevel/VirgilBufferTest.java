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
package com.virgilsecurity.sdk.highlevel;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * Test case for {@link VirgilBuffer}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilBufferTest {

    private static final String TEXT = "Just a text";
    private byte[] BYTES = ConvertionUtils.toBytes(TEXT);

    @Test(expected = NullArgumentException.class)
    public void create_null() {
        new VirgilBuffer(null);
    }

    @Test(expected = EmptyArgumentException.class)
    public void create_empty() {
        new VirgilBuffer(new byte[0]);
    }

    @Test
    public void create() {
        new VirgilBuffer(TEXT.getBytes());
    }

    @Test
    public void getBytes() {
        VirgilBuffer buffer = new VirgilBuffer(BYTES);
        byte[] restored = buffer.getBytes();

        assertEquals(BYTES.length, restored.length);
        assertArrayEquals(BYTES, restored);
    }

    @Test
    public void from_bytes() {
        byte[] bytes = TEXT.getBytes();
        VirgilBuffer buffer = VirgilBuffer.from(bytes);
        byte[] restored = buffer.getBytes();

        assertEquals(bytes.length, restored.length);
        assertArrayEquals(bytes, restored);
    }

    @Test
    public void from_string() {
        VirgilBuffer buffer = VirgilBuffer.from(TEXT);
        byte[] restored = buffer.getBytes();

        assertEquals(BYTES.length, restored.length);
        assertArrayEquals(BYTES, restored);
    }

    @Test
    public void from_utf8() {
        VirgilBuffer buffer = VirgilBuffer.from(TEXT, StringEncoding.UTF8);
        byte[] restored = buffer.getBytes();

        assertEquals(BYTES.length, restored.length);
        assertArrayEquals(BYTES, restored);
    }

    @Test
    public void toString_text() {
        VirgilBuffer buffer = VirgilBuffer.from(TEXT);
        assertEquals(TEXT, buffer.toString());
    }

    @Test
    public void toString_utf8() {
        VirgilBuffer buffer = VirgilBuffer.from(TEXT);
        assertEquals(TEXT, buffer.toString(StringEncoding.UTF8));
    }
}
