/*
 * Copyright (C) 2014 The CyanogenMod Project
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
package com.cyanogenmod.account.setup;

import android.app.Fragment;
import android.content.Context;
import android.content.pm.ThemeUtils;
import android.content.res.CustomTheme;
import android.content.res.ThemeManager;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.Switch;

import com.cyanogenmod.account.R;
import com.cyanogenmod.account.ui.SetupPageFragment;
import com.cyanogenmod.account.util.CMAccountUtils;

public class PersonalizationPage extends Page {

    private static final String TAG = PersonalizationPage.class.getSimpleName();
    private Bundle mPageState;

    public PersonalizationPage(Context context, SetupDataCallbacks callbacks, int titleResourceId) {
        super(context, callbacks, titleResourceId);
    }

    @Override
    public Fragment createFragment() {
        Bundle args = new Bundle();
        args.putString(Page.KEY_PAGE_ARGUMENT, getKey());
        mPageState = getData();

        PrivacySettingsFragment fragment = new PrivacySettingsFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public int getNextButtonResId() {
        return R.string.next;
    }

    public class PrivacySettingsFragment extends SetupPageFragment {

        @Override
        protected void setUpPage() {
            if (hideWhisperPush(getActivity())) {
                ViewGroup whisperPushLayout = (ViewGroup) mRootView.findViewById(R.id.whisperpush);
                if (whisperPushLayout != null) {
                    whisperPushLayout.setVisibility(View.GONE);
                }
            }
            Switch whisperPushSwitch = (Switch) mRootView.findViewById(R.id.whisperpush_switch);
            mPageState.putBoolean("register", whisperPushSwitch.isChecked());
            whisperPushSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                    mPageState.putBoolean("register", b);
                }
            });


            Switch defaultThemeSwitch = (Switch) mRootView.findViewById(R.id.apply_default_theme_switch);
            if (hideThemeSwitch(getActivity())) {
                ViewGroup themeLayout = (ViewGroup) mRootView.findViewById(R.id.apply_default_theme);
                if (themeLayout != null) {
                    themeLayout.setVisibility(View.GONE);
                }
            } else {
                defaultThemeSwitch.setChecked(true);
            }
            mPageState.putBoolean("apply_default_theme", defaultThemeSwitch.isChecked());
            defaultThemeSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                    mPageState.putBoolean("apply_default_theme", b);
                }
            });
        }

        @Override
        protected int getLayoutResource() {
            return R.layout.setup_personalization_page;
        }

        @Override
        protected int getTitleResource() {
            return R.string.setup_personalization;
        }
    }

    protected static boolean hideWhisperPush(Context context) {
        return CMAccountUtils.isGSMPhone(context) && CMAccountUtils.isSimMissing(context);
    }

    protected static boolean hideThemeSwitch(Context context) {
        return ThemeUtils.getDefaultThemePackageName(context) == CustomTheme.HOLO_DEFAULT;
    }

    public static boolean skipPage(Context context) {
        return hideWhisperPush(context) && hideThemeSwitch(context);
    }
}