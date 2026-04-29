# Changelog

## 0.7.5

### Security

- **Pluggable secure token storage.** Added optional `storage` field to `RetterClientConfig` accepting any `RetterStorage` adapter (`getItem` / `setItem` / `removeItem`). Apps can now back token persistence with `expo-secure-store` or `react-native-keychain` instead of plain AsyncStorage. Closes pentest finding **MA-02** (and **MA-15** when used with `expo-secure-store` defaults).
- **Split-key persistence.** Auth payload (`RIO_AUTH.<projectId>`) and Firebase custom token (`RIO_FB.<projectId>`) are now stored under separate keys so each entry stays under SecureStore's 2 KB Android limit.
- **Slimmer storage payload.** Decoded JWT payloads, derived `accessTokenExpiresAt` / `refreshTokenExpiresAt`, and other derivable fields are no longer persisted; the SDK reconstructs them from raw tokens on read. Only the clock-skew (`diff`) value is kept since it must be captured at token-receipt time.
- **One-shot legacy migration.** First read after upgrade transparently moves any existing `RIO_TOKENS_KEY.<projectId>` blob from AsyncStorage into the configured storage and deletes the AsyncStorage entry. Existing sessions survive the upgrade.

### Backward compatibility

- `storage` is optional. When omitted, the SDK falls back to AsyncStorage, preserving prior behavior. Migrating to a secure adapter is a single config change.
- `RetterTokenData` public shape is unchanged. `accessTokenDecoded`, `refreshTokenDecoded`, and the `ExpiresAt` fields are still populated on every read.
