import { Buffer } from 'buffer'
import uuid from 'react-native-uuid'
import AsyncStorage from '@react-native-async-storage/async-storage'

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
