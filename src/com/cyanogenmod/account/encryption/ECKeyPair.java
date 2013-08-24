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
package com.cyanogenmod.account.encryption;

import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.UUID;

public class ECKeyPair {
    private ECPoint publicKey;
    private BigInteger privateKey;
    private String keyId;

    public ECKeyPair(ECPoint publicKey, BigInteger privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.keyId = UUID.randomUUID().toString();
    }

    public ECKeyPair(ECPoint publicKey, BigInteger privateKey, String keyId) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.keyId = keyId;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public String getKeyId() {
        return keyId;
    }
}