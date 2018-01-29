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

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import com.google.gson.reflect.TypeToken;
import com.sun.jmx.snmp.Timestamp;
import com.virgilsecurity.sdk.client.model.RawCardContent;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.common.ClassForSerialization;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

import static org.junit.Assert.*;

public class CrossCompatibilityTest {

    @Test
    public void importCardModelJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(ConvertionUtils.toBase64String(cardContent.getPublicKeyData()),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void autoByteToBase64StringSerialization() { // FIXME: 1/29/18 Check where we can change String with byte[] in models - gson automatically will transform it
        ClassForSerialization classForSerialization =
                new ClassForSerialization("Petro", "Grigorovych".getBytes());

        String serialized = ConvertionUtils.serializeToJson(classForSerialization);

        Map<String, Object> mapJson = ConvertionUtils.deserializeFromJson(serialized);
        String data = "";
        for (Map.Entry<String, Object> entry : mapJson.entrySet())
            if (entry.getKey().equals("data"))
                data = (String) mapJson.get(entry.getKey());

        assertEquals(ConvertionUtils.base64ToString(data), "Grigorovych");
    }

    @Test
    public void importExportJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelString() throws IOException {
        String importedFromString = readFile("t1_exported_as_str.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKeyData(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void importExportString() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelJsonFullSignatures() throws IOException {
        String importedFromJson = readFile("t2_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKeyData(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertEquals(cardContent.getPreviousCardId(), "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
        assertEquals(cardModel.getSignatures().size(), 3);

        assertEquals(cardModel.getSignatures().get(0).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQFfpZUY8aD0SzmU7rJh49bm4CD7wyTtYeTWLddJzJDS+0HpST3DulxMfBjQfWq5Y3upj49odzQNhOaATz3fF3gg=");
        assertEquals(cardModel.getSignatures().get(0).getSignerId(),
                     "e6fbcad760b3d89610a96230718a6c0522d0dbb1dd264273401d9634c1bb5be0");
        assertEquals(cardModel.getSignatures().get(0).getSignerType(),
                     "self");
        assertNull(cardModel.getSignatures().get(0).getSnapshot());

        assertEquals(cardModel.getSignatures().get(1).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQKLcj0Tx0dOTET6vmFmc+xk9BKOfsidoXdcl0BWr4hwL3SaEiQR3E2PT7VcVr6yIKMEneUmmlvL/mqbRCZ1dwQo=");
        assertEquals(cardModel.getSignatures().get(1).getSignerId(),
                     "5b748aa6890d90c4fe199300f8ff10b4e1fdfd50140774ca6b03adb121ee94e1");
        assertEquals(cardModel.getSignatures().get(1).getSignerType(),
                     "virgil");
        assertNull(cardModel.getSignatures().get(1).getSnapshot());

        assertEquals(cardModel.getSignatures().get(2).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQHqRoiTjhbbDZfYLsXexjdywiNOH2HlEe84yZaWKIo5AiKGTAVsE31JgSBCCNvBn5FBymNSpbtNGH3Td17xePAQ=");
        assertEquals(cardModel.getSignatures().get(2).getSignerId(),
                     "d729624f302f03f4cf83062bd24af9c44aa35b11670a155300bf3a8560dfa30f");
        assertEquals(cardModel.getSignatures().get(2).getSignerType(),
                     "extra");
        assertNull(cardModel.getSignatures().get(2).getSnapshot());
    }

    @Test
    public void importExportJsonFullSignatures() throws IOException {
        String importedFromJson = readFile("t2_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelStringFullSignatures() throws IOException {
        String importedFromString = readFile("t2_exported_as_str.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKeyData(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);

//        fixme
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
