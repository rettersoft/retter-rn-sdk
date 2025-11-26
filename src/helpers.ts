import { Buffer } from 'buffer'
import uuid from 'react-native-uuid'
import AsyncStorage from '@react-native-async-storage/async-storage'

// AsyncStorage'ın mevcut olup olmadığını kontrol et
if (!AsyncStorage) {
    throw new Error('@react-native-async-storage/async-storage is required but not installed. Please install it in your React Native project.')
}

function getAnalytics() {
    try {
        const analyticsModule = require('@react-native-firebase/analytics')
        return analyticsModule.default()
    } catch (e) {
        return null
    }
}
export function base64Encode(str: string): string {
    return Buffer.from(str).toString('base64')
}

export function sort(data: any): any {
    if (data == null) {
        return data
    } else if (Array.isArray(data)) {
        return data.sort().map(sort)
    } else if (typeof data === 'object') {
        return Object.keys(data)
            .sort()
            .reduce((acc, key) => {
                acc[key] = sort(data[key])
                return acc
            }, {} as Record<string, any>)
    }

    return data
}

export function isTokenValid(token: string): boolean {
    if (token && token !== 'undefined' && token !== 'null') {
        return Boolean(token);
    }
    return false;
}

export async function getInstallationId() {
    try {
        const id = await AsyncStorage.getItem('RIO_INSTALLATION_ID')
        if (id) return id
        const newId = uuid.v4().toString()
        await AsyncStorage.setItem('RIO_INSTALLATION_ID', newId)
        return newId
    } catch (err) {
        return '';
    }
}

export async function logAnalyticsEvent(eventName: string, params?: { [key: string]: any }) {
    try {
        const analytics = getAnalytics()
        if (analytics) {
            await analytics.logEvent(eventName, {
                ...params,
                timestamp: new Date().toISOString(),
            })
        }
    } catch (error) {
        // Analytics hatası durumunda sessizce devam et
        console.log('[RetterSDK] Analytics log error:', error)
    }
}

export async function logEvent(eventName: string, params?: { [key: string]: any }, level: 'log' | 'info' | 'warn' | 'error' = 'info') {
    await logAnalyticsEvent(`retter_sdk_${eventName.toLowerCase()}`, {
        ...params,
        level,
    })
}

export async function logError(error: Error | any, context?: { [key: string]: any }) {
    try {
        const errorMessage = error?.message || String(error)
        const errorStack = error?.stack || ''

        // Analytics'e error event logla
        await logAnalyticsEvent('retter_sdk_error', {
            error_message: errorMessage,
            error_stack: errorStack.substring(0, 500), // Stack trace'i kısalt
            ...context,
        })
    } catch (logError) {
        console.log('[RetterSDK] Error logging failed:', logError)
    }
}
