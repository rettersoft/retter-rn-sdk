import { RetterClientConfig, RetterRegion } from './types'

// Amazon Trust Services Root CA SPKI SHA-256 hashes (base64-encoded)
// Verified from https://www.amazontrust.com/repository/
// These are static — Amazon does not rotate root CAs.
export const AMAZON_ROOT_CA_HASHES: string[] = [
    '++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=', // Amazon Root CA 1 (RSA 2048)
    'f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=', // Amazon Root CA 2 (RSA 4096)
    'NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=', // Amazon Root CA 3 (EC P-256)
    '9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=', // Amazon Root CA 4 (EC P-384)
    'KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=', // Starfield Services Root CA G2
]

const RETTER_DOMAINS: Record<number, string> = {
    [RetterRegion.euWest1]: 'api.retter.io',
    [RetterRegion.euWest1Beta]: 'test-api.retter.io',
}

export async function setupSslPinning(config: RetterClientConfig): Promise<void> {
    if (config.sslPinningEnabled !== true) {
        return
    }

    try {
        const {
            isSslPinningAvailable,
            initializeSslPinning,
        } = require('react-native-ssl-public-key-pinning')

        if (!isSslPinningAvailable()) {
            console.warn(
                '[RetterSDK] SSL pinning native module not available. ' +
                'Ensure react-native-ssl-public-key-pinning is properly linked.'
            )
            return
        }

        const domain = config.url
            ? config.url.replace(/^https?:\/\//, '').split('/')[0]
            : RETTER_DOMAINS[config.region ?? RetterRegion.euWest1] ?? 'api.retter.io'

        await initializeSslPinning({
            [domain]: {
                includeSubdomains: true,
                publicKeyHashes: AMAZON_ROOT_CA_HASHES,
            },
        })

        console.log(`[RetterSDK] SSL pinning initialized for ${domain}`)
    } catch (error: any) {
        if (error.code === 'MODULE_NOT_FOUND' || error.message?.includes('Cannot find module')) {
            console.warn(
                '[RetterSDK] react-native-ssl-public-key-pinning is not installed. ' +
                'SSL pinning is disabled. Install it to enable SSL pinning.'
            )
        } else {
            console.error('[RetterSDK] Failed to initialize SSL pinning:', error)
        }
    }
}

export async function teardownSslPinning(): Promise<void> {
    try {
        const { disableSslPinning } = require('react-native-ssl-public-key-pinning')
        await disableSslPinning()
    } catch {
        // Library not installed, nothing to tear down
    }
}
