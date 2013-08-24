/*
 * Copyright (C) 2013 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cyanogenmod.account.gcm.model;

import com.cyanogenmod.account.util.CMAccountUtils;
import com.cyanogenmod.account.util.EncryptionUtils;
import com.google.gson.Gson;
import com.google.gson.annotations.Expose;

public class EncryptedMessage implements Message {
    @Expose
    private String ciphertext;

    @Expose
    private String initializationVector;

    @Expose
    private String signature;

    public String getCiphertext() {
        return ciphertext;
    }

    public String getInitializationVector() {
        return initializationVector;
    }

    public String toJson() {
        return new Gson().toJson(this);
    }

    public String getSignature() {
        return signature;
    }

    public void encrypt(String symmetricKey) {
        byte[] symmetricKeyBytes = CMAccountUtils.decodeHex(symmetricKey);
        String json = toJson();

        EncryptionUtils.AES.CipherResult result = EncryptionUtils.AES.encrypt(json, symmetricKeyBytes);
        ciphertext = result.getCiphertext();
        initializationVector = result.getInitializationVector();
    }

    public void sign(byte[] hmacSecret) {
        String signatureBody = ciphertext + ":" + initializationVector;
        signature = EncryptionUtils.HMAC.getSignature(hmacSecret, signatureBody);
    }
}
