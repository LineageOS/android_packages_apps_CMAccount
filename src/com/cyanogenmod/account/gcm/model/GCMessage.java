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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.spongycastle.math.ec.ECPoint;

public class GCMessage {
    public static final String COMMAND_SECURE_MESSAGE = "secure_message";

    private String command;
    private String key_id;
    private String signature;
    private EncryptedMessage message;
    private String message_signature;
    private PublicKeyMessage public_key;
    private AccountMessage account;

    public String getCommand() {
        return command;
    }

    public AccountMessage getAccount() {
        return account;
    }

    public ECPoint getPublicKey() {
        return public_key.getPublicKey();
    }

    public String getPublicKeySignature() {
        return public_key.getSignature();
    }

    public String getKeyId() {
        return key_id;
    }

    public EncryptedMessage getEncryptedMessage() {
        return message;
    }

    public String toJson() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }
}
