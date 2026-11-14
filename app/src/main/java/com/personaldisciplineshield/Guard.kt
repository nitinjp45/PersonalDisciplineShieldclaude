package com.personaldisciplineshield

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.widget.Toast
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Impulse-proof lock. Weakening any protection needs: password -> wait DELAY_MS -> short WINDOW_MS.
 * The secret can be any text (letters, digits, symbols). Names keep "Pin" for compatibility.
 * Tip: let a trusted person set the password so you do not know it.
 */
object Guard {
    private const val PIN_HASH = "pin_hash"
    private const val PIN_SALT = "pin_salt"
    private const val PIN_SCHEME = "pin_scheme" // absent = legacy salted SHA-256, else the PBKDF2 algorithm name
    private const val UNLOCK_AT = "unlock_at_elapsed"
    private const val FAILS = "pin_fails"
    private const val LOCKOUT_UNTIL = "pin_lockout_until"

    const val DELAY_MS = 15 * 60 * 1000L   // change to taste (e.g. 24h = 24*60*60*1000L)
    const val WINDOW_MS = 5 * 60 * 1000L
    const val MIN_LENGTH = 16 // characters; 16 digits is fine too
    private const val ITERATIONS = 150_000

    fun hasPin(c: Context) = Prefs.getString(c, PIN_HASH) != null

    private fun bestAlgorithm(): String = try {
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); "PBKDF2WithHmacSHA256"
    } catch (_: Exception) {
        "PBKDF2WithHmacSHA1" // Android 6-7
    }

    private fun pbkdf2(alg: String, secret: String, salt: ByteArray): String {
        val spec = PBEKeySpec(secret.toCharArray(), salt, ITERATIONS, 256)
        try {
            val key = SecretKeyFactory.getInstance(alg).generateSecret(spec).encoded
            return Base64.encodeToString(key, Base64.NO_WRAP)
        } finally {
            spec.clearPassword()
        }
    }

    private fun legacyHash(secret: String, salt: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        return Base64.encodeToString(md.digest(secret.toByteArray()), Base64.NO_WRAP)
    }

    private fun store(c: Context, secret: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val alg = bestAlgorithm()
        Prefs.putString(c, PIN_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
        Prefs.putString(c, PIN_SCHEME, alg)
        Prefs.putString(c, PIN_HASH, pbkdf2(alg, secret, salt))
    }

    fun setPin(c: Context, secret: String) {
        store(c, secret)
        Prefs.putLong(c, FAILS, 0L)
        Prefs.putLong(c, LOCKOUT_UNTIL, 0L)
        lock(c)
    }

    /** Milliseconds left in the "too many wrong attempts" lockout. */
    fun lockoutMs(c: Context): Long {
        val until = Prefs.getLong(c, LOCKOUT_UNTIL)
        val now = SystemClock.elapsedRealtime()
        if (until > now + 60 * 60 * 1000L) return 0L // value from before a reboot
        return (until - now).coerceAtLeast(0L)
    }

    fun checkPin(c: Context, secret: String): Boolean {
        if (lockoutMs(c) > 0) return false
        val salt = Prefs.getString(c, PIN_SALT)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val expected = Prefs.getString(c, PIN_HASH) ?: return false
        val scheme = Prefs.getString(c, PIN_SCHEME)
        val actual = try {
            if (scheme == null) legacyHash(secret, salt) else pbkdf2(scheme, secret, salt)
        } catch (_: Exception) { return false }
        val ok = MessageDigest.isEqual(actual.toByteArray(), expected.toByteArray())
        if (ok) {
            Prefs.putLong(c, FAILS, 0L)
            if (scheme == null) store(c, secret) // upgrade an old PIN hash to PBKDF2
        } else {
            val fails = Prefs.getLong(c, FAILS) + 1
            Prefs.putLong(c, FAILS, fails)
            if (fails % 5 == 0L) {
                // 5, 10, 20, then 40 minutes
                val step = ((fails / 5) - 1).coerceAtMost(3).toInt()
                Prefs.putLong(c, LOCKOUT_UNTIL, SystemClock.elapsedRealtime() + (5 * 60 * 1000L shl step))
            }
        }
        return ok
    }

    /** Uses the monotonic clock (changing the phone's date cannot shorten the wait).
     *  A value from before a reboot is impossible in the new boot, so it is treated as "none". */
    private fun unlockAt(c: Context): Long {
        val v = Prefs.getLong(c, UNLOCK_AT)
        return if (v > SystemClock.elapsedRealtime() + DELAY_MS) 0L else v
    }

    fun requestUnlock(c: Context) =
        Prefs.putLong(c, UNLOCK_AT, SystemClock.elapsedRealtime() + DELAY_MS)

    fun lock(c: Context) = Prefs.putLong(c, UNLOCK_AT, 0L)

    /** No password set = guard not armed = everything is changeable. */
    fun isUnlocked(c: Context): Boolean {
        if (!hasPin(c)) return true
        val at = unlockAt(c)
        val now = SystemClock.elapsedRealtime()
        return at in 1L..now && now < at + WINDOW_MS
    }

    fun waitingMs(c: Context): Long =
        (unlockAt(c) - SystemClock.elapsedRealtime()).coerceAtLeast(0L)

    fun openRemainingMs(c: Context): Long =
        (unlockAt(c) + WINDOW_MS - SystemClock.elapsedRealtime()).coerceAtLeast(0L)

    /** Call before any action that weakens protection. */
    fun require(c: Context): Boolean {
        if (isUnlocked(c)) return true
        val w = waitingMs(c)
        val msg = if (w > 0) "Locked. Unlock opens in ${w / 60000 + 1} min."
        else "Locked. Open Advanced protection > Request unlock."
        Toast.makeText(c, msg, Toast.LENGTH_LONG).show()
        return false
    }
}
