package com.example.realmencryption

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.example.realmencryption.utils.Constants
import io.realm.Realm
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.math.abs

@TargetApi(23)
class KeyEncryption private constructor() {

    private val keyStore = getKeyStore()

    companion object {

        private val instance = KeyEncryption()

        private const val CIPHER_API_22_AND_LOWER = "RSA/ECB/PKCS1Padding"
        private const val CIPHER_API_23_AND_HIGHER = (KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7)

        private val CIPHER = if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M)
            CIPHER_API_23_AND_HIGHER else CIPHER_API_22_AND_LOWER

        //////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////////

        fun getOrGenerateKey(context: Context): ByteArray {
            var encryptedKey = instance.getEncryptedKeyFromShareds(context)
            if (encryptedKey == null || encryptedKey.isEmpty() || !instance.isKeystoreContainsKey()) {
                val newRealmKey = instance.generateNewRealmKey()
                instance.generateKeyInKeyStore(context)
                encryptedKey = instance.encryptKeyAndSaveToShareds(context, newRealmKey)
                Arrays.fill(newRealmKey, 0.toByte())
            }

            return instance.decryptKey(encryptedKey)
        }

        fun resetKey(context: Context) {
            instance.getSharedPreferences(context).edit().clear().apply()
        }
    }

    private fun decryptKey(ivAndEncryptedKey: ByteArray): ByteArray {
        val cipher = getCipher()
        val byteBuffer = ByteBuffer.wrap(ivAndEncryptedKey)
        byteBuffer.order(ByteOrder.BIG_ENDIAN)
        val ivLength = byteBuffer.int

        val initializationVector = if (ivLength > 0) ByteArray(ivLength) else null
        val encryptedKey = ByteArray(ivAndEncryptedKey.size - Int.SIZE_BITS - ivLength)

        initializationVector?.let {
            byteBuffer[it]
        }

        byteBuffer[encryptedKey]

        return try {
            val publicKey = keyStore.getKey(Constants.KEYSTORE_REALM_KEY_ALIAS, null)

            initializationVector?.let {
                val ivSpec = IvParameterSpec(it)
                cipher.init(Cipher.DECRYPT_MODE, publicKey, ivSpec)

            } ?: run {
                cipher.init(Cipher.DECRYPT_MODE, publicKey)
            }

            cipher.doFinal(encryptedKey)
        } catch (exception: Exception) {
            throw RuntimeException(exception)
        }
    }

    private fun encryptKeyAndSaveToShareds(context: Context, realmKey: ByteArray): ByteArray {
        val cipher = getCipher()
        val initializationVector: ByteArray
        val encryptedKeyForRealm: ByteArray

        try {
            val publicKey: Key

            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
                publicKey = keyStore.getKey(Constants.KEYSTORE_REALM_KEY_ALIAS, null)
            } else {
                val privateKeyEntry: KeyStore.PrivateKeyEntry
                try {
                    privateKeyEntry = keyStore.getEntry(
                        Constants.KEYSTORE_REALM_KEY_ALIAS,
                        null
                    ) as KeyStore.PrivateKeyEntry
                    publicKey = privateKeyEntry.certificate.publicKey
                } catch (exception: Exception) {
                    throw RuntimeException(exception)
                }
            }

            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            encryptedKeyForRealm = cipher.doFinal(realmKey)
            initializationVector = cipher.iv
        } catch (exception: Exception) {
            throw RuntimeException(exception)
        }

        val ivAndEncryptedKey =
            ByteArray(Int.SIZE_BITS + initializationVector.size + encryptedKeyForRealm.size)
        val byteBuffer = ByteBuffer.wrap(ivAndEncryptedKey)
        byteBuffer.order(ByteOrder.BIG_ENDIAN)
        byteBuffer.putInt(initializationVector.size)

        if (initializationVector.isNotEmpty()) {
            byteBuffer.put(initializationVector)
        }

        byteBuffer.put(encryptedKeyForRealm)
        saveEncryptedKeyToShareds(context, ivAndEncryptedKey)

        return ivAndEncryptedKey
    }

    private fun getCipher(): Cipher {
        return try {
            Cipher.getInstance(CIPHER)
        } catch (exception: Exception) {
            throw RuntimeException(exception)
        }
    }

    private fun generateKeyInKeyStore(context: Context) {
        try {
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    Constants.ANDROID_KEYSTORE_PROVIDER_NAME
                )

                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    Constants.KEYSTORE_REALM_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    .build()

                try {
                    keyGenerator.init(keyGenParameterSpec)
                } catch (exception: Exception) {
                    throw RuntimeException(exception)
                }

                keyGenerator.generateKey()
            } else {
                val keyPairGeneratorSpec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(Constants.KEYSTORE_REALM_KEY_ALIAS)
                    .setSubject(X500Principal("CN=${Constants.KEYSTORE_REALM_KEY_ALIAS}"))
                    .setSerialNumber(BigInteger.valueOf(abs(Constants.KEYSTORE_REALM_KEY_ALIAS.hashCode()).toLong()))
                    .setStartDate(GregorianCalendar().time)
                    .setEndDate(GregorianCalendar().apply {
                        add(Calendar.YEAR, 25)
                    }.time)
                    .build()

                val keyPairGenerator = KeyPairGenerator.getInstance(
                    Constants.RSA,
                    Constants.ANDROID_KEYSTORE_PROVIDER_NAME
                )
                keyPairGenerator.initialize(keyPairGeneratorSpec)
                keyPairGenerator.generateKeyPair()
            }
        } catch (exception: Exception) {
            throw RuntimeException(exception)
        }
    }

    private fun isKeystoreContainsKey(): Boolean {
        return try {
            keyStore.containsAlias(Constants.KEYSTORE_REALM_KEY_ALIAS)
        } catch (exception: Exception) {
            throw RuntimeException(exception)
        }
    }

    private fun getKeyStore(): KeyStore {
        return try {
            KeyStore.getInstance(Constants.ANDROID_KEYSTORE_PROVIDER_NAME).apply {
                load(null)
            }
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    private fun getEncryptedKeyFromShareds(context: Context): ByteArray? {
        val stringBase64 =
            getSharedPreferences(context).getString(Constants.SP_REALM_KEY, null) ?: return null
        return Base64.decode(stringBase64, Base64.DEFAULT)
    }

    private fun saveEncryptedKeyToShareds(context: Context, key: ByteArray) {
        getSharedPreferences(context)
            .edit()
            .putString(Constants.SP_REALM_KEY, Base64.encodeToString(key, Base64.NO_WRAP))
            .apply()
    }

    private fun getSharedPreferences(context: Context): SharedPreferences {
        return context.getSharedPreferences(Constants.SHARED_PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun generateNewRealmKey(): ByteArray {
        return ByteArray(Realm.ENCRYPTION_KEY_LENGTH).apply {
            SecureRandom().nextBytes(this)
        }
    }
}