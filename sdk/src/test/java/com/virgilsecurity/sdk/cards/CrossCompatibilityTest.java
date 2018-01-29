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

package com.virgilsecurity.sdk.cards;

import com.sun.jmx.snmp.Timestamp;
import com.virgilsecurity.sdk.client.model.RawCardContent;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import static org.junit.Assert.*;

public class CrossCompatibilityTest {

    @Test
    public void importCardModelJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(ConvertionUtils.toBase64String(cardContent.getPublicKeyData()),"MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void importExportJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void base64String() {
        String hello = "Hello";
        String b64helloStr = ConvertionUtils.toBase64String(hello);
        byte[] b64helloBytes = b64helloStr.getBytes();

        String decodedFromb64HelloStr = new String(b64helloBytes);
        assertEquals(decodedFromb64HelloStr, hello);
    }

    @Test
    public void importCardModelString() throws IOException {
        String importedFromString = readFile("t1_exported_as_str.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(ConvertionUtils.toBase64String(cardContent.getPublicKeyData()),"MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void parseSnapsot() {
        String snapshot = "eyJpZGVudGl0eSI6IlRFU1QiLCJwdWJsaWNfa2V5IjoiTUNvd0JRWURLMlZ3QXlFQVpUdHZkVmE2YnhLUENWcDZVW" +
                "nBwMFhJNDdhN3lNTlNNb2FYZ0R5VHQvak09IiwidmVyc2lvbiI6IjUuMCIsImNyZWF0ZWRfYXQiOjE1MTc5MDQ2NzN9";

        RawCardContent cardContent = ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(snapshot),
                                                                         RawCardContent.class);

        String serializedSnapshot = ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(cardContent));
        assertEquals(snapshot, serializedSnapshot);
    }

    private String readFile(String name) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        File file = new File("/Users/danylooliinyk/Downloads/", name);

        FileReader fileReader = new FileReader(file);
        BufferedReader buff = new BufferedReader(fileReader);

        while (((line = buff.readLine()) != null)) {
            stringBuilder.append(line);
        }

        buff.close();

        return stringBuilder.toString();
    }
}
