package com.spectrum.cm.biometrics

import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.navigation.NavigationView
import android.os.Bundle
import com.spectrum.cm.biometrics.R
import com.google.android.material.floatingactionbutton.FloatingActionButton
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import com.google.android.material.snackbar.Snackbar
import androidx.drawerlayout.widget.DrawerLayout
import androidx.appcompat.app.ActionBarDrawerToggle
import androidx.core.view.GravityCompat
import com.spectrum.cm.biometrics.MainActivity
import android.widget.Toast
import androidx.biometric.BiometricPrompt.PromptInfo
import kotlin.Throws
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import androidx.activity.viewModels
import androidx.appcompat.widget.Toolbar
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import java.lang.Exception
import java.lang.RuntimeException
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.*
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity(), NavigationView.OnNavigationItemSelectedListener {
    private var mToBeSignedMessage: String? = null
    private val loginWithPasswordViewModel by viewModels<LoginViewModel>()

    private lateinit var biometricPrompt: BiometricPrompt

    private val cryptographyManager = CryptographyManager()
    private val ciphertextWrapper
        get() = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            applicationContext,
            SHARED_PREFS_FILENAME,
            Context.MODE_PRIVATE,
            CIPHERTEXT_WRAPPER
        )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        val fab = findViewById<FloatingActionButton>(R.id.fab)
        fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }
        val drawer = findViewById<DrawerLayout>(R.id.drawer_layout)
        val toggle = ActionBarDrawerToggle(
            this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close
        )
        drawer.addDrawerListener(toggle)
        toggle.syncState()
        val navigationView = findViewById<NavigationView>(R.id.nav_view)
        navigationView.setNavigationItemSelectedListener(this)

        loginWithPasswordViewModel.loginResult.observe(this, androidx.lifecycle.Observer {
            val loginResult = it
            if (loginResult.success) {
                Log.i(TAG, "onCreate: SettingsActivity")
                startActivity(Intent(this@MainActivity, SettingsActivity::class.java))

            }
        })
    }

    override fun onBackPressed() {
        val drawer = findViewById<DrawerLayout>(R.id.drawer_layout)
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        val id = item.itemId
        return if (id == R.id.action_settings) {
            showBiometricPromptForDecryption()
            true
        } else super.onOptionsItemSelected(item)
    }
    private fun showBiometricPromptForDecryption() {
        ciphertextWrapper?.let { textWrapper ->
            val secretKeyName = getString(R.string.secret_key_name)
            val cipher = cryptographyManager.getInitializedCipherForDecryption(
                secretKeyName, textWrapper.initializationVector
            )
            biometricPrompt =
                BiometricPromptUtils.createBiometricPrompt(
                    this,
                    ::decryptServerTokenFromStorage
                )
            val promptInfo = BiometricPromptUtils.createPromptInfo(this)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun decryptServerTokenFromStorage(authResult: BiometricPrompt.AuthenticationResult) {
        ciphertextWrapper?.let { textWrapper ->
            authResult.cryptoObject?.cipher?.let {
                val plaintext =
                    cryptographyManager.decryptData(textWrapper.ciphertext, it)
                SampleAppUser.fakeToken = plaintext
                // Now that you have the token, you can query server for everything else
                // the only reason we call this fakeToken is because we didn't really get it from
                // the server. In your case, you will have gotten it from the server the first time
                // and therefore, it's a real token.
                startActivity(Intent(this@MainActivity, SettingsActivity::class.java))

//                updateApp(getString(R.string.already_signedin))
            }
        }
    }

    override fun onNavigationItemSelected(item: MenuItem): Boolean {
        // Handle navigation view item clicks here.
        val id = item.itemId
        if (id == R.id.nav_register) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try registration")
                // Generate keypair and init signature
                val signature: Signature?
                try {
                    val keyPair = generateKeyPair(KEY_NAME, true)
                    // Send public key part of key pair to the server, this public key will be used for authentication
                    mToBeSignedMessage =
                        Base64.encodeToString(keyPair.public.encoded, Base64.URL_SAFE) +
                                ":" +
                                KEY_NAME +
                                ":" +  // Generated by the server to protect against replay attack
                                "12345"
                    signature = initSignature(KEY_NAME)
                } catch (e: Exception) {
                    throw RuntimeException(e)
                }

                // Create biometricPrompt
                showBiometricPrompt(signature)
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show()
            }
        } else if (id == R.id.nav_authenticate) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try authentication")

                // Init signature
                val signature: Signature?
                try {
                    // Send key name and challenge to the server, this message will be verified with registered public key on the server
                    mToBeSignedMessage = KEY_NAME +
                            ":" +  // Generated by the server to protect against replay attack
                            "12345"
                    signature = initSignature(KEY_NAME)
                } catch (e: Exception) {
                    throw RuntimeException(e)
                }

                // Create biometricPrompt
                showBiometricPrompt(signature)
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show()
            }
        }
        val drawer = findViewById<DrawerLayout>(R.id.drawer_layout)
        drawer.closeDrawer(GravityCompat.START)
        return true
    }

    private fun showBiometricPrompt(signature: Signature?) {
        val authenticationCallback = authenticationCallback
        val mBiometricPrompt = BiometricPrompt(this, mainThreadExecutor, authenticationCallback)

        // Set prompt info
        val promptInfo = PromptInfo.Builder()
            .setDescription("Charter Biometric Library")
            .setTitle("Auth")
            .setSubtitle("")
            .setNegativeButtonText("Cancel")
            .build()

        // Show biometric prompt
        if (signature != null) {
            Log.i(TAG, "Show biometric prompt")
            mBiometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
        }
    }// Error// Normally, ToBeSignedMessage and Signature are sent to the server and then verified

    // Callback for biometric authentication result
    private val authenticationCallback: BiometricPrompt.AuthenticationCallback
        private get() =// Callback for biometric authentication result
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Log.e(TAG, "Error code: " + errorCode + "error String: " + errString)
                    super.onAuthenticationError(errorCode, errString)
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    Log.i(TAG, "onAuthenticationSucceeded")
                    super.onAuthenticationSucceeded(result)
                    if (result.cryptoObject != null &&
                        result.cryptoObject!!.signature != null
                    ) {
                        try {
                            val signature = result.cryptoObject!!
                                .signature
                            signature!!.update(mToBeSignedMessage!!.toByteArray())
                            val signatureString = Base64.encodeToString(
                                signature.sign(), Base64.URL_SAFE
                            )
                            // Normally, ToBeSignedMessage and Signature are sent to the server and then verified
                            Log.i(TAG, "Message: $mToBeSignedMessage")
                            Log.i(TAG, "Signature (Base64 Encoded): $signatureString")
                            Toast.makeText(
                                applicationContext,
                                "$mToBeSignedMessage:$signatureString",
                                Toast.LENGTH_SHORT
                            ).show()
                        } catch (e: SignatureException) {
                            throw RuntimeException()
                        }
                    } else {
                        // Error
                        Toast.makeText(applicationContext, "Something wrong", Toast.LENGTH_SHORT)
                            .show()
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                }
            }

    @Throws(Exception::class)
    private fun generateKeyPair(
        keyName: String,
        invalidatedByBiometricEnrollment: Boolean
    ): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            ) // Require the user to authenticate with a biometric to authorize every use of the key
            .setUserAuthenticationRequired(true)

        // Generated keys will be invalidated if the biometric templates are added more to user device
        if (Build.VERSION.SDK_INT >= 24) {
            builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
        }
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    @Throws(Exception::class)
    private fun getKeyPair(keyName: String): KeyPair? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            val publicKey = keyStore.getCertificate(keyName).publicKey
            // Get private key
            val privateKey = keyStore.getKey(keyName, null) as PrivateKey
            // Return a key pair
            return KeyPair(publicKey, privateKey)
        }
        return null
    }

    @Throws(Exception::class)
    private fun initSignature(keyName: String): Signature? {
        val keyPair = getKeyPair(keyName)
        if (keyPair != null) {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(keyPair.private)
            return signature
        }
        return null
    }

    private val mainThreadExecutor: Executor
        private get() = MainThreadExecutor()

    private class MainThreadExecutor : Executor {
        private val handler = Handler(Looper.getMainLooper())
        override fun execute(r: Runnable) {
            handler.post(r)
        }
    }

    /**
     * Indicate whether this device can authenticate the user with strong biometrics
     * @return true if there are any available strong biometric sensors and biometrics are enrolled on the device, if not, return false
     */
    private fun canAuthenticateWithStrongBiometrics(): Boolean {
        return BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }

    companion object {
        private val TAG = MainActivity::class.java.name

        // Unique identifier of a key pair
        private val KEY_NAME = UUID.randomUUID().toString()
    }
}