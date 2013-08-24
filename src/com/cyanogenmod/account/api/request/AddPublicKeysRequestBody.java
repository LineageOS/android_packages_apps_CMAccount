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
package com.cyanogenmod.account.api.request;

import android.content.Context;
import com.cyanogenmod.account.encryption.ECKeyPair;
import com.cyanogenmod.account.util.CMAccountUtils;
import com.google.gson.Gson;
import org.spongycastle.math.ec.ECPoint;

import java.util.ArrayList;
import java.util.List;

public class AddPublicKeysRequestBody {
    private List<KeyPair> public_keys;
    private String device_id;

    public AddPublicKeysRequestBody(Context context, List<ECKeyPair> keyPairs) {
        device_id = CMAccountUtils.getUniqueDeviceId(context);
        public_keys = new ArrayList<KeyPair>();

        for (ECKeyPair keyPair : keyPairs) {
            String key_id = keyPair.getKeyId();
            ECPoint publicKey = keyPair.getPublicKey();

            public_keys.add(new KeyPair(publicKey, key_id));
        }
    }

    public String toJson(Gson gson) {
        return gson.toJson(this);
    }

    private static class KeyPair {
        private String x;
        private String y;
        private String key_id;

        public KeyPair(ECPoint publicKey, String key_id) {
            this.x = publicKey.getX().toBigInteger().toString();
            this.y = publicKey.getY().toBigInteger().toString();
            this.key_id = key_id;
        }
    }
}
