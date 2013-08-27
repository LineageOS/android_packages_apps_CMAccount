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

package com.cyanogenmod.account.util;

import android.util.Base64;
import android.util.Log;
import com.cyanogenmod.account.encryption.ECKeyPair;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EncryptionUtils {
    private static final String TAG = EncryptionUtils.class.getSimpleName();

    public static class ECDH {
        private static final ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        private static BigInteger generatePrivateKey() {
            // Generate private key.
            BigInteger n = ecParameterSpec.getN();
            BigInteger n1 = n.subtract(BigInteger.ONE);
            BigInteger r = new BigInteger(n.bitLength(), new SecureRandom());
            BigInteger privateKey = r.mod(n1).add(BigInteger.ONE);
            return privateKey;
        }

        private static ECPoint generatePublicKey(BigInteger privateKey) {
            return ecParameterSpec.getG().multiply(privateKey);
        }

        public static ECKeyPair generateKeyPair() {
            BigInteger privateKey = generatePrivateKey();
            ECPoint publicKey = generatePublicKey(privateKey);
            return new ECKeyPair(publicKey, privateKey);
        }

        public static ECPoint getPublicKey(BigInteger x, BigInteger y) {
            return ecParameterSpec.getCurve().createPoint(x, y, false);
        }

        public static ECPoint getPublicKey(String hexX, String hexY) {
            BigInteger x = new BigInteger(CMAccountUtils.decodeHex(hexX));
            BigInteger y = new BigInteger(CMAccountUtils.decodeHex(hexY));
            return getPublicKey(x, y);
        }

        public static byte[] calculateSecret(BigInteger privateKey, ECPoint publicKey) {
            ECPoint.Fp P = new ECPoint.Fp(ecParameterSpec.getCurve(), publicKey.getX(), publicKey.getY());
            ECPoint S = P.multiply(privateKey);
            byte[] keyBytes = S.getX().toBigInteger().toByteArray();

            // BigIntegers are stored in two's complement notation.  The first byte determines the sign.
            // Because of this, there may be a signing byte, giving us a 264bit key, but  we need a 256bit key.
            // If there is a signing byte, drop it.  Both sides must do this.
            if (keyBytes.length == 33) {
                keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
            }

            return keyBytes;
        }
    }

    public static class PBKDF2 {
        public static byte[] getDerivedKey(String password, String salt) {
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = Base64.decode(salt, Base64.NO_WRAP);

            try {
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec keySpec = new PBEKeySpec(passwordChars, saltBytes, 1024, 256);
                SecretKey secretKey = keyFactory.generateSecret(keySpec);
                return secretKey.getEncoded();
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "NoSuchAlgorithmException", e);
                throw new AssertionError(e);
            } catch (InvalidKeySpecException e) {
                Log.e(TAG, "InvalidKeySpecException", e);
                throw new AssertionError(e);
            }
        }
    }

    public static class HMAC {
        public static String getSignature(byte[] key, String message) {
            try {
                Mac hmac = Mac.getInstance("HmacSHA256");
                Key secretKey = new SecretKeySpec(key, "HmacSHA256");
                hmac.init(secretKey);
                hmac.update(message.getBytes());
                return CMAccountUtils.encodeHex(hmac.doFinal());
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "NoSuchAlgorithmException", e);
                throw new AssertionError(e);
            } catch (InvalidKeyException e) {
                Log.e(TAG, "InvalidKeyException", e);
                throw new AssertionError(e);
            }
        }
    }

    public static class AES {
        public static String decrypt(String _ciphertext, byte[] key, String _initializationVector) {
            byte[] initializationVector = Base64.decode(_initializationVector, Base64.DEFAULT);
            byte[] ciphertext = Base64.decode(_ciphertext, Base64.DEFAULT);

            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(initializationVector);

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                byte[] plaintext = cipher.doFinal(ciphertext);

                return new String(plaintext);
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "NoSuchAlgorithimException", e);
                throw new AssertionError(e);
            } catch (NoSuchPaddingException e) {
                Log.e(TAG, "NoSuchPaddingException", e);
                throw new AssertionError(e);
            } catch (InvalidKeyException e) {
                Log.e(TAG, "InvalidKeyException", e);
                throw new AssertionError(e);
            } catch (IllegalBlockSizeException e) {
                Log.e(TAG, "IllegalBlockSizeException", e);
                throw new AssertionError(e);
            } catch (BadPaddingException e) {
                Log.e(TAG, "BadPaddingException", e);
                throw new AssertionError(e);
            } catch (InvalidAlgorithmParameterException e) {
                Log.e(TAG, "InvalidAlgorithmParameterException", e);
                throw new AssertionError(e);
            }
        }

        public static CipherResult encrypt(String plaintext, byte[] key) {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                byte[] initializationVector = cipher.getIV();
                byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

                String encodedCiphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
                String encodedInitializationVector = Base64.encodeToString(initializationVector, Base64.NO_WRAP);

                return new CipherResult(encodedCiphertext, encodedInitializationVector);
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "NoSuchAlgorithimException", e);
                throw new AssertionError(e);
            } catch (NoSuchPaddingException e) {
                Log.e(TAG, "NoSuchPaddingException", e);
                throw new AssertionError(e);
            } catch (InvalidKeyException e) {
                Log.e(TAG, "InvalidKeyException", e);
                throw new AssertionError(e);
            } catch (IllegalBlockSizeException e) {
                Log.e(TAG, "IllegalBlockSizeException", e);
                throw new AssertionError(e);
            } catch (BadPaddingException e) {
                Log.e(TAG, "BadPaddingException", e);
                throw new AssertionError(e);
            }
        }

        public static class CipherResult {
            private String ciphertext;
            private String initializationVector;

            private CipherResult(String ciphertext, String initializationVector) {
                this.ciphertext = ciphertext;
                this.initializationVector = initializationVector;
            }

            public String getCiphertext() {
                return ciphertext;
            }

            public String getInitializationVector() {
                return initializationVector;
            }
        }
    }

    public static String generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[128];
        secureRandom.nextBytes(salt);
        return Base64.encodeToString(salt, Base64.NO_WRAP);
    }
}
