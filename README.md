# Personal Discipline Shield — Stage 4

Stage 3A.3 (DNS-over-VPN) plus:
- PIN + waiting-time lock (Guard) — weakening any protection needs PIN -> 15 min wait -> 5 min window
- Device Admin (uninstall protection, screen lock after 3 strikes in 5 min)
- Accessibility service: blocked keywords (search boxes, browser URL bars), blocked apps,
  guard for Settings/uninstall screens that show this app, optional explicit-image screen check
- Bigger adult list from assets/blocklist_adult.txt + domain-name heuristic
- Auto-restart of VPN after reboot

## Setup order on the phone
1. Install APK, open app, Enable DNS Protection (VPN prompt).
2. Advanced protection > Enable Device Admin.
3. Android 13+: Settings > Apps > Personal Discipline Shield > ⋮ > Allow restricted settings.
4. Advanced protection > Open Accessibility settings > enable the service.
5. Add keywords, choose apps, (optional) drop nsfw.tflite into app/src/main/assets/ and enable image guard.
6. LAST: set the PIN (ideally by a trusted person). After this nothing can be weakened without the wait.

## Optional: strongest uninstall protection (Device Owner)
On a fresh/reset phone with no accounts added:
  adb shell dpm set-device-owner com.personaldisciplineshield/.ShieldAdminReceiver
Then uninstall is blocked at OS level and Always-on VPN is registered.

## Limits (be honest with yourself)
Not tamper-proof against a determined owner: safe mode, adb, factory reset, a second browser with
its own DoH, or Settings in a language/OEM skin not covered by the guard can bypass it.
Image guard is probabilistic. Keyword guard sees only text Android exposes to accessibility.

## Added after Stage 4
- Settings lockdown (Advanced protection): while PIN-locked, only allow-listed Settings pages
  (Wi-Fi, Bluetooth, hotspot, saved networks...) open. Quick Settings tiles are unaffected.
  "Last blocked Settings screen" helps you add missing page titles.
- WhatsApp: Channels/Updates tab is bounced back to Chats (English UI only).

## MIUI 12 / Redmi Note 10 notes
- Before setting the PIN: Autostart ON, Battery saver "No restrictions", lock the app in Recents.
- Settings lockdown also covers MIUI Security app and Battery (powerkeeper) screens.
- MIUI Settings home is blocked (class MiuiSettings and row-title markers); use the shortcut buttons or Quick Settings tiles.
- Second space / Dual apps are not covered; lockdown blocks their Settings pages while locked.

## 0.5.0 hardening
- Lock secret is now a password (any characters, 6+), stored with PBKDF2 (150k iterations, random salt);
  old PIN hashes are upgraded on the next successful unlock. 5 wrong tries => timed lockout.
- DNS-over-TLS (port 853) to Cloudflare / Google / Quad9 with certificate + host name checks,
  one reused TLS connection. Optional Strict mode disables the plain-DNS fallback.
- GitHub Actions are pinned to commit SHAs (version tag kept in the comment).

## 0.5.3
- DNS provider selector (Automatic, Cloudflare, Cloudflare Family, Google, Quad9, AdGuard, AdGuard Family, Custom).
  Strict encrypted DNS: no plain fallback; a Custom provider (e.g. NextDNS) never switches to another provider.
  Custom host is stored in the app only. Failed lookups return SERVFAIL immediately.
- Settings lockdown no longer pauses during the unlock window; allowed state is re-checked on content changes;
  reads text and content descriptions.
- WhatsApp: whole Updates tab; tap-by-coordinates fallback when the Chats tab is not clickable.
- Option to disable the adult domain-name heuristic.
