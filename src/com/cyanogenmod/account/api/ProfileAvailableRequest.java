/*
 * Copyright (C) 2013-2016 The CyanogenMod Project
 * Copyright (C) 2016-2017 The LineageOS Project
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

package com.cyanogenmod.account.api;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import com.android.volley.NetworkResponse;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.cyanogenmod.account.CMAccount;
import com.cyanogenmod.account.auth.AuthClient;

import android.util.Log;

public class ProfileAvailableRequest extends CMAccountRequest<ProfileAvailableResponse> {

    private static final String TAG = ProfileAvailableRequest.class.getSimpleName();

    public ProfileAvailableRequest(String email,
            Response.Listener<ProfileAvailableResponse> listener, Response.ErrorListener errorListener) {
        super(AuthClient.PROFILE_AVAILABLE_URI, listener, errorListener);
        if (email != null) addParameter(PARAM_EMAIL, email);
    }

    @Override
    protected Response<ProfileAvailableResponse> parseNetworkResponse(NetworkResponse response) {
        String jsonResponse = new String(response.data);
        if (CMAccount.DEBUG) Log.d(TAG, "jsonResponse=" + jsonResponse);
        try {
            ProfileAvailableResponse res = new Gson().fromJson(jsonResponse, ProfileAvailableResponse.class);
            return Response.success(res, getCacheEntry());
        } catch (JsonSyntaxException e) {
            return Response.error(new VolleyError(e));
        }
    }
}
