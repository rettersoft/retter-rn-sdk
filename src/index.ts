import AsyncStorage from '@react-native-async-storage/async-storage'
import { Observable } from './observable'
import {
    RetterActions,
    RetterAuthChangedEvent,
    RetterAuthStatus,
    RetterCallResponse,
    RetterClientConfig,
    RetterCloudObject,
    RetterCloudObjectCall,
    RetterCloudObjectConfig,
    RetterCloudObjectItem,
    RetterCloudObjectRequest,
    RetterCloudObjectState,
    RetterCloudObjectStaticCall,
    RetterRegion,
    RetterRegionConfig,
    RetterStorage,
    RetterTokenData,
    RetterTokenPayload,
} from './types'
import jwtDecode from 'jwt-decode'
import { getFirestore, doc, onSnapshot } from '@react-native-firebase/firestore'
import { getAuth, signInWithCustomToken, signOut } from '@react-native-firebase/auth'
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'
import { base64Encode, getInstallationId, sort } from './helpers'
import { setupSslPinning } from './ssl-pinning'

export * from './types'
export { AMAZON_ROOT_CA_HASHES } from './ssl-pinning'

const DEFAULT_RETRY_DELAY = 50 // in ms
const DEFAULT_RETRY_COUNT = 3
const DEFAULT_RETRY_RATE = 1.5

// Backward-compatible fallback. Apps holding sensitive tokens should pass
// a SecureStore/Keychain-backed adapter via `config.storage`.
const defaultStorage: RetterStorage = {
    getItem: (key) => AsyncStorage.getItem(key),
    setItem: (key, value) => AsyncStorage.setItem(key, value),
    removeItem: (key) => AsyncStorage.removeItem(key),
}

const RetterRegions: RetterRegionConfig[] = [
    {
        id: RetterRegion.euWest1,
        url: 'api.retter.io',
    },
    {
        id: RetterRegion.euWest1Beta,
        url: 'test-api.retter.io',
    },
]

export default class Retter {
    private static instances: Retter[] = []

    private initialized = false

    private clientConfig?: RetterClientConfig

    private cloudObjects: RetterCloudObjectItem[] = []

    private listeners: { [key: string]: any } = {}

    // Auth payload (access/refresh + clock skew). Kept under SecureStore's
    // 2 KB Android limit by splitting Firebase data into a separate key.
    private authStorageKey?: string

    // Firebase custom-token + project metadata.
    private firebaseStorageKey?: string

    // Pre-0.7.5 single-blob key in AsyncStorage; only read for one-shot migration.
    private legacyTokenStorageKey?: string

    private storage: RetterStorage = defaultStorage

    private authStatusSubject: Observable<RetterAuthChangedEvent>

    private refreshTokenPromise: Promise<any> | null = null

    private firebaseSignInFailed = false;

    private sslPinningReady: Promise<void> = Promise.resolve()

    protected axiosInstance?: AxiosInstance

    public static getInstance(config: RetterClientConfig): Retter {
        const instance = this.instances.find(
            (instance) => instance.clientConfig?.projectId === config.projectId
        )
        if (instance) return instance

        const newInstance = new Retter(config)
        this.instances.push(newInstance)
        return newInstance
    }

    protected constructor(config: RetterClientConfig) {
        if (this.initialized) throw new Error('SDK already initialized.')
        this.initialized = true
        this.clientConfig = config

        this.authStorageKey = `RIO_AUTH.${config.projectId}`
        this.firebaseStorageKey = `RIO_FB.${config.projectId}`
        this.legacyTokenStorageKey = `RIO_TOKENS_KEY.${config.projectId}`
        if (config.storage) this.storage = config.storage
        if (!this.clientConfig.region)
            this.clientConfig.region = RetterRegion.euWest1

        if (!this.clientConfig.retryConfig) this.clientConfig.retryConfig = {}
        if (!this.clientConfig.retryConfig.delay)
            this.clientConfig.retryConfig.delay = DEFAULT_RETRY_DELAY
        if (!this.clientConfig.retryConfig.count)
            this.clientConfig.retryConfig.count = DEFAULT_RETRY_COUNT
        if (!this.clientConfig.retryConfig.rate)
            this.clientConfig.retryConfig.rate = DEFAULT_RETRY_RATE


        this.sslPinningReady = setupSslPinning(config)
        this.createAxiosInstance()
        this.authStatusSubject = new Observable<RetterAuthChangedEvent>(
            () => {
                this.initAuth()
            }
        )
    }

    // #region Request
    protected createAxiosInstance() {
        const axiosConfig: AxiosRequestConfig = {
            responseType: 'json',
            headers: {
                'Content-Type': 'application/json',
                'cache-control': `max-age=0`,
            },
            timeout: 30000,
        }

        this.axiosInstance! = axios.create(axiosConfig)
    }

    private async getValidAccessToken(): Promise<string | null> {
        const tokens = await this.getCurrentTokenData()

        // No tokens — unauthenticated call (e.g. login)
        if (!tokens || !this.isValidToken(tokens.accessToken)) {
            return null
        }

        const now = Math.floor(Date.now() / 1000)
        const safeNow = now + 30 + (tokens.diff ?? 0)
        const accessTokenDecoded = tokens.accessTokenDecoded

        // Token is still valid
        if (!accessTokenDecoded || accessTokenDecoded.exp >= safeNow) {
            return tokens.accessToken
        }

        // Access token expired - check refresh token
        const refreshTokenDecoded = tokens.refreshTokenDecoded
        if (refreshTokenDecoded && refreshTokenDecoded.exp < safeNow) {
            await this.signOut('getValidAccessToken: Both tokens expired')
            throw new Error('Session expired - please login again')
        }

        // Refresh needed - reuse existing promise or create new one
        if (!this.refreshTokenPromise) {
            this.refreshTokenPromise = this.refreshToken()
                .then((response) => response.accessToken)
                //@ts-ignore
                .finally(() => { this.refreshTokenPromise = null })
        }

        const newToken = await this.refreshTokenPromise
        if (!newToken) {
            await this.signOut('getValidAccessToken: Refresh returned empty token')
            throw new Error('Token refresh failed - please login again')
        }

        return newToken
    }

    protected async makeAPIRequest<T>(
        action: RetterActions,
        data: RetterCloudObjectConfig,
        retryCount: number = 0
    ): Promise<RetterCallResponse<T>> {
        await this.sslPinningReady
        try {
            const endpoint = this.generateEndpoint(action, data)
            const accessToken = await this.getValidAccessToken()

            const newData = { ...data }
            if (accessToken) {
                newData.headers = {
                    ...newData.headers,
                    Authorization: `Bearer ${accessToken}`,
                }
            }

            return await this.executeRequest(endpoint, newData)
        } catch (error: any) {
            // 403/401 from server means token is invalid despite our local checks
            // (e.g. token revoked server-side, clock skew, etc.)
            if (this.isAuthError(error) && !this.isAuthErrorHandled(retryCount)) {
                // Force refresh token and retry once
                this.refreshTokenPromise = null // Clear any stale promise
                try {
                    const tokenData = await this.refreshToken()
                    const newData = { ...data }
                    newData.headers = {
                        ...newData.headers,
                        Authorization: `Bearer ${tokenData.accessToken}`,
                    }
                    const endpoint = this.generateEndpoint(action, data)
                    return await this.executeRequest(endpoint, newData)
                } catch (refreshError) {
                    // Refresh failed - user session is truly invalid
                    // signOut is already called inside refreshToken on auth/server errors
                    throw error // throw original error
                }
            }

            if (this.isRetryableError(error) && retryCount < 3) {
                const delay = Math.min(1000 * Math.pow(2, retryCount), 5000)
                await new Promise(resolve => setTimeout(resolve, delay))
                return this.makeAPIRequest(action, data, retryCount + 1)
            }
            throw error
        }
    }

    private isAuthErrorHandled(retryCount: number): boolean {
        // Only handle auth error once (retryCount === 0 means first attempt)
        return retryCount > 0
    }

    protected async executeRequest(
        url: string,
        config: RetterCloudObjectConfig
    ): Promise<any> {
        const queryStringParams = { ...config.queryStringParams }
        if (!queryStringParams.__culture)
            queryStringParams.__culture = this.clientConfig?.culture ?? 'en-us'
        if (!queryStringParams.__platform && this.clientConfig?.platform)
            queryStringParams.__platform = this.clientConfig.platform

        if (config.httpMethod === 'get' && config.body) {
            const data = base64Encode(JSON.stringify(sort(config.body)))
            delete config.body
            queryStringParams.data = data
            queryStringParams.__isbase64 = 'true'
        }

        const headers = { ...config.headers }
        headers.installationId = await getInstallationId()

        return new Promise((resolve, reject) => {
            this.axiosInstance!({
                url,
                method: config.httpMethod ?? 'POST',
                headers,
                params: queryStringParams,
                data: config.body,
            })
                .then((response) => {
                    resolve(response)
                })
                .catch((error) => {
                    reject(error)
                })
        })
    }

    protected generateEndpoint(
        action: RetterActions,
        data: RetterCloudObjectConfig
    ): string {
        const prefixes: Record<RetterActions, string> = {
            [RetterActions.COS_CALL]: 'CALL',
            [RetterActions.COS_LIST]: 'LIST',
            [RetterActions.COS_STATE]: 'STATE',
            [RetterActions.COS_INSTANCE]: 'INSTANCE',
            [RetterActions.COS_STATIC_CALL]: 'CALL',
        }

        let url = `/${prefixes[action]}`
        if (data.classId) url += `/${data.classId}`

        if (action === RetterActions.COS_INSTANCE) {
            const instanceId = data.key
                ? `${data.key.name}!${data.key.value}`
                : data.instanceId

            if (instanceId) url += `/${instanceId}`
        }

        if (action === RetterActions.COS_STATE) {
            url += `/${data.instanceId}`
        }

        if (action === RetterActions.COS_LIST) {
            // do nothing
        }

        if (
            action === RetterActions.COS_CALL ||
            action === RetterActions.COS_STATIC_CALL
        ) {
            url += `/${data.method}`
            if (data.instanceId) url += `/${data.instanceId}`
            if (data.pathParams) url += `/${data.pathParams}`
        }

        return this.buildUrl(this.clientConfig!.projectId, url)
    }

    protected buildUrl(projectId: string, path: string) {
        const prefix = this.clientConfig?.url
            ? `${this.clientConfig.url}`
            : `${projectId}.${RetterRegions.find(
                (region) => region.id === this.clientConfig?.region
            )?.url
            }`

        return `https://${prefix}/${this.clientConfig?.projectId}${path}`
    }
    // #endregion

    // #region Firebase
    protected async initFirebase(tokenData?: RetterTokenData) {
        try {
            const firebaseConfig = tokenData?.firebase
            if (!firebaseConfig) {
                console.log('[RetterSDK] initFirebase: No firebase config provided, skipping Firebase init');
                return
            }

            const authInstance = getAuth()

            try {
                const firebaseCustomToken = await signInWithCustomToken(authInstance, firebaseConfig.customToken);
                this.firebaseSignInFailed = false;
                return firebaseCustomToken;
            } catch (err: any) {
                this.firebaseSignInFailed = true;
                return err;
            }
        } catch (err: any) {

            console.log('[RetterSDK] initFirebase: Firebase initialization error', err)
            return err;
        }
    }

    protected getFirebaseListener(
        queue: any,
        collectionPath: string,
        documentId: string,
        listenerKey?: string
    ): () => void {
        // Remove leading slash from collection path if present
        const cleanCollection = collectionPath.startsWith('/') ? collectionPath.slice(1) : collectionPath

        if (!documentId || documentId.trim() === '') {
            console.log('[RetterSDK] getFirebaseListener: documentId is empty, cannot create listener')
            queue.next({})
            return () => { }
        }

        // Check if Firebase auth is initialized before creating listener
        const authInstance = getAuth()
        if (!authInstance.currentUser) {
            console.log('[RetterSDK] getFirebaseListener: Firebase user not authenticated, cannot create listener')
            queue.next({})
            return () => { }
        }

        const db = getFirestore()
        const documentRef = doc(db, cleanCollection, documentId)

        let hasError = false
        let retryAttempted = false

        const unsubscribe = onSnapshot(documentRef, (doc: any) => {
            // Reset error flag on successful read
            hasError = false

            if (!doc || !doc.exists()) {
                queue.next({})
                return
            }

            const data = Object.assign({}, doc.data())
            for (const key of Object.keys(data)) {
                if (key.startsWith('__')) {
                    delete data[key]
                }
            }
            queue.next(data)
        }, async (error: any) => {
            console.log('[RetterSDK] getFirebaseListener: Firebase listener error:', error)

            // Clean up listener if permission denied
            if (error?.code === 'permission-denied' || error?.code === 'firestore/permission-denied') {
                hasError = true

                // Try to refresh token and recreate listener once
                if (!retryAttempted && listenerKey) {
                    retryAttempted = true
                    console.log('[RetterSDK] getFirebaseListener: Permission denied, attempting to refresh Firebase auth')

                    // Mark listener as being recreated to prevent race conditions
                    const recreatingKey = `${listenerKey}_recreating`
                    if (this.listeners[recreatingKey]) {
                        console.log('[RetterSDK] getFirebaseListener: Listener already being recreated, skipping')
                        return
                    }
                    this.listeners[recreatingKey] = true

                    try {
                        this.firebaseSignInFailed = true;
                        await this.refreshToken()

                        // Wait a bit for Firebase to reinitialize
                        await new Promise(resolve => setTimeout(resolve, 500))

                        // Check if auth is now valid
                        const newAuthInstance = getAuth()
                        if (newAuthInstance.currentUser) {
                            // Unsubscribe old listener first
                            unsubscribe()

                            // Clean up old listener reference
                            if (this.listeners[listenerKey]) {
                                delete this.listeners[listenerKey]
                            }

                            // Recreate listener with refreshed auth
                            console.log('[RetterSDK] getFirebaseListener: Recreating listener, will receive current document state')
                            const newListener = this.getFirebaseListener(
                                queue,
                                collectionPath,
                                documentId,
                                listenerKey
                            )
                            this.listeners[listenerKey] = newListener
                        }
                    } catch (refreshError) {
                        console.log('[RetterSDK] getFirebaseListener: Failed to refresh Firebase auth:', refreshError)
                    } finally {
                        // Always clean up recreation flag
                        delete this.listeners[recreatingKey]
                    }
                    return
                }

                // If refresh failed or already attempted, clean up listener
                console.log('[RetterSDK] getFirebaseListener: Permission denied, cleaning up listener')
                if (listenerKey && this.listeners[listenerKey]) {
                    delete this.listeners[listenerKey]
                }
                // Send empty data to queue to indicate error state
                queue.next({})
            } else {
                hasError = true
            }
        })

        return unsubscribe
    }

    protected async getFirebaseState(config: RetterCloudObjectConfig) {
        if (!this.clientConfig) throw new Error('Client config not found.')

        const { projectId } = this.clientConfig

        const user = await this.getCurrentUser()
        if (!user) {
            console.log('[RetterSDK] getFirebaseState: No user currently signed in, cannot create Firebase state')
        }

        // Get Firebase auth UID for Firestore rules compatibility
        const authInstance = getAuth()
        const firebaseUid = authInstance.currentUser?.uid

        const unsubscribers: (() => void)[] = []

        const observables = {
            role: new Observable<any>(() => { }),
            user: new Observable<any>(() => { }),
            public: new Observable<any>(() => { }),
        }

        const listenerPrefix = `${projectId}_${config.classId}_${config.instanceId}`

        const state = {
            role: {
                observable: observables.role,
                subscribe: (callback: (data: any) => void) => {
                    const listenerKey = `${listenerPrefix}_role`
                    if (!this.listeners[listenerKey]) {
                        try {
                            const listener = this.getFirebaseListener(
                                observables.role,
                                `projects/${projectId}/classes/${config.classId}/instances/${config.instanceId}/roleState`,
                                user?.identity!,
                                listenerKey
                            )
                            this.listeners[listenerKey] = listener
                        } catch (error) {
                            console.log('[RetterSDK] getFirebaseState: Failed to create role listener:', error)
                        }
                    }

                    return observables.role.subscribe(callback)
                },
            },
            user: {
                observable: observables.user,
                subscribe: (callback: (data: any) => void) => {
                    const listenerKey = `${listenerPrefix}_user`
                    if (!this.listeners[listenerKey]) {
                        try {
                            // Use Firebase auth.uid instead of user.userId for Firestore rules compatibility
                            const documentId = firebaseUid || user?.userId
                            if (!documentId) {
                                console.log('[RetterSDK] getFirebaseState: No Firebase UID or userId available, cannot create user listener')
                                return observables.user.subscribe(callback)
                            }
                            const listener = this.getFirebaseListener(
                                observables.user,
                                `projects/${projectId}/classes/${config.classId}/instances/${config.instanceId}/userState`,
                                documentId,
                                listenerKey
                            )
                            this.listeners[listenerKey] = listener
                        } catch (error) {
                            console.log('[RetterSDK] getFirebaseState: Failed to create user listener:', error)
                        }
                    }

                    return observables.user.subscribe(callback)
                },
            },
            public: {
                observable: observables.public,
                subscribe: (callback: (data: any) => void) => {
                    const listenerKey = `${listenerPrefix}_public`
                    if (!this.listeners[listenerKey]) {
                        try {
                            const listener = this.getFirebaseListener(
                                observables.public,
                                `projects/${projectId}/classes/${config.classId}/instances`,
                                config.instanceId!,
                                listenerKey
                            )
                            this.listeners[listenerKey] = listener
                        } catch (error) {
                            console.log('[RetterSDK] getFirebaseState: Failed to create public listener:', error)
                        }
                    }

                    return observables.public.subscribe(callback)
                },
            },
        }

        return { state, unsubscribers }
    }
    // #endregion

    // #region Cloud Object
    public async getCloudObject(
        config: RetterCloudObjectConfig
    ): Promise<RetterCloudObject> {
        if (!this.initialized) throw new Error('Retter SDK not initialized.')

        let instance
        if (!config.instanceId && !config.useLocal) {
            const { data } = await this.makeAPIRequest<
                Partial<RetterCloudObject>
            >(RetterActions.COS_INSTANCE, config)
            instance = data
            config.instanceId = data.instanceId
        }

        const seekedObject = this.cloudObjects.find(
            (object) =>
                object.config.classId === config.classId &&
                object.config.instanceId === config.instanceId
        )

        if (seekedObject) {
            return seekedObject
        }

        let state;
        try {
            // Sadece user varsa Firebase state oluştur
            const user = await this.getCurrentUser()
            if (user) {
                const firebaseState = await this.getFirebaseState(config)
                state = firebaseState.state
            } else {
                // User yoksa boş state oluştur
                state = {
                    role: { observable: new Observable<any>(() => { }), subscribe: () => ({ unsubscribe: () => { } }) },
                    user: { observable: new Observable<any>(() => { }), subscribe: () => ({ unsubscribe: () => { } }) },
                    public: { observable: new Observable<any>(() => { }), subscribe: () => ({ unsubscribe: () => { } }) }
                }
            }
        } catch (error) {
            console.log('[RetterSDK] getCloudObject: Failed to get Firebase state:', error);
        }

        const call = async <T>(
            params: RetterCloudObjectCall
        ): Promise<RetterCallResponse<T>> => {
            params.retryConfig = {
                ...this.clientConfig!.retryConfig,
                ...params.retryConfig,
            }
            try {
                return await this.makeAPIRequest(RetterActions.COS_CALL, {
                    ...params,
                    classId: config.classId,
                    instanceId: config.instanceId,
                })
            } catch (error: any) {
                --params.retryConfig.count!
                params.retryConfig.delay! *= params.retryConfig.rate!
                if (
                    error.response &&
                    error.response.status === 570 &&
                    params.retryConfig.count! > 0
                ) {
                    await new Promise((r) =>
                        setTimeout(r, params.retryConfig!.delay!)
                    )
                    return await call(params)
                } else {
                    throw error
                }
            }
        }

        const getState = async (
            params?: RetterCloudObjectRequest
        ): Promise<RetterCallResponse<RetterCloudObjectState>> => {
            return await this.makeAPIRequest<RetterCloudObjectState>(
                RetterActions.COS_STATE,
                {
                    ...params,
                    classId: config.classId,
                    instanceId: config.instanceId,
                }
            )
        }

        const listInstances = async (
            params?: RetterCloudObjectRequest
        ): Promise<string[]> => {
            const { data } = await this.makeAPIRequest<{
                instanceIds: string[]
            }>(RetterActions.COS_LIST, { ...params, classId: config.classId })

            return data.instanceIds
        }

        const retVal = {
            call,
            state,
            getState,
            listInstances,
            methods: instance?.methods ?? [],
            response: instance?.response ?? null,
            instanceId: config.instanceId!,
            // @ts-ignore
            isNewInstance: instance?.newInstance ?? false,
        }

        this.cloudObjects.push({ ...retVal, config, unsubscribers: [] })
        return retVal
    }

    protected async clearCloudObjects(shouldSignOut: boolean = true) {
        try {
            // Clear listeners
            //@ts-ignore
            const listeners = Object.values(this.listeners)
            if (listeners.length > 0) {
                listeners.map((i: any) => i())

                this.cloudObjects.map((i) => {
                    i.state?.role.queue?.complete()
                    i.state?.user.queue?.complete()
                    i.state?.public.queue?.complete()
                })
            }
            this.listeners = {}

            this.cloudObjects.map((i) => i.unsubscribers.map((u) => u()))
            this.cloudObjects = []

            if (shouldSignOut) {
                const authInstance = getAuth()
                const currentUser = authInstance.currentUser
                if (currentUser) {
                    await signOut(authInstance)
                }
            }
        } catch (error) {
            console.log('[RetterSDK] clearCloudObjects: Error clearing cloud objects:', error)
        }
    }
    // #endregion


    private isValidToken(token: string | undefined | null): boolean {
        return typeof token === 'string' &&
            token.length > 0 &&
            token !== 'undefined' &&
            token !== 'null'
    }

    private isNetworkError(error: any): boolean {
        return error.code === 'NETWORK_ERROR' ||
            error.code === 'ECONNABORTED' ||
            error.code === 'ENOTFOUND' ||
            error.code === 'ECONNREFUSED' ||
            error.message?.includes('Network Error') ||
            error.message?.includes('timeout')
    }

    private isAuthError(error: any): boolean {
        const message = error.message || ''
        const responseMessage = error.response?.data?.message || ''

        return message.includes("Unexpected error occured in TOKEN") ||
            message.includes('jwt expired') ||
            responseMessage.includes('jwt expired') ||
            (error.response && error.response.status === 401) ||
            (error.response && error.response.status === 403) ||
            message.includes('ACCESS_DENIED')
    }

    private isServerError(error: any): boolean {
        return error.response && error.response.status >= 500
    }

    private isRetryableError(error: any): boolean {
        return this.isNetworkError(error) ||
            (error.response && error.response.status === 503) || // Service unavailable
            (error.response && error.response.status === 502)    // Bad gateway
    }

    // #region Static Call
    public async makeStaticCall<T>(
        params: RetterCloudObjectStaticCall
    ): Promise<RetterCallResponse<T>> {
        if (!this.initialized) throw new Error('Retter SDK not initialized.')

        return await this.makeAPIRequest<T>(RetterActions.COS_STATIC_CALL, {
            ...params,
            classId: params.classId,
        })
    }
    // #endregion

    // #region Auth
    protected async initAuth() {
        let tokens
        try {
            tokens = await this.getCurrentTokenData()
        } catch (error) {
            console.log('[RetterSDK] initAuth: Failed to read token data:', error)
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_OUT,
                message: 'Token storage read failed',
            })
            return
        }

        if (!tokens) {
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_OUT,
                message: 'First Init access token is undefined',
            })
            return
        }

        try {
            const now = Math.floor(Date.now() / 1000)
            const safeNow = now + 30 + (tokens.diff ?? 0)

            // Check if refresh token is expired — if so, session is dead
            const refreshTokenDecoded = tokens.refreshTokenDecoded
            if (refreshTokenDecoded && refreshTokenDecoded.exp < safeNow) {
                console.log('[RetterSDK] initAuth: Refresh token expired, signing out')
                await this.clearTokenData()
                await this.clearCloudObjects()
                this.fireAuthStatusChangedEvent({
                    authStatus: RetterAuthStatus.SIGNED_OUT,
                    message: 'Session expired - refresh token is no longer valid',
                })
                return
            }

            // If access token expired but refresh token is valid, refresh now
            const accessTokenDecoded = tokens.accessTokenDecoded
            if (accessTokenDecoded && accessTokenDecoded.exp < safeNow) {
                console.log('[RetterSDK] initAuth: Access token expired, refreshing before init')
                try {
                    const newTokenData = await this.refreshToken()
                    await this.initFirebase(newTokenData)
                    this.fireAuthStatusChangedEvent({
                        authStatus: RetterAuthStatus.SIGNED_IN,
                        uid: newTokenData.accessTokenDecoded?.userId,
                        identity: newTokenData.accessTokenDecoded?.identity,
                    })
                    return
                } catch (refreshError) {
                    console.log('[RetterSDK] initAuth: Token refresh failed during init:', refreshError)
                    // refreshToken already handles signOut on auth/server errors
                    return
                }
            }

            // Token is still valid
            await this.initFirebase(tokens)
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_IN,
                uid: tokens.accessTokenDecoded?.userId,
                identity: tokens.accessTokenDecoded?.identity,
            })
        } catch (error) {
            console.error('[RetterSDK] initAuth: Auth initialization error:', error)
        }
    }

    public async authenticateWithCustomToken(
        token: string
    ): Promise<RetterAuthChangedEvent> {
        await this.sslPinningReady
        if (!this.clientConfig) throw new Error('Client config not found.')
        const { projectId } = this.clientConfig

        const response = await this.axiosInstance!({
            url: this.buildUrl(projectId, '/TOKEN/auth'),
            method: 'post',
            data: { customToken: token },
        })

        const tokenData = this.formatTokenData(response.data)
        await this.storeTokenData(tokenData)

        this.clearCloudObjects(false) // Don't sign out during login process
        await this.initFirebase(tokenData)

        const authEvent = {
            authStatus: RetterAuthStatus.SIGNED_IN,
            uid: tokenData.accessTokenDecoded?.userId,
            identity: tokenData.accessTokenDecoded?.identity,
        }

        this.fireAuthStatusChangedEvent(authEvent)
        return authEvent
    }

    protected async refreshToken(): Promise<RetterTokenData> {
        await this.sslPinningReady
        if (!this.clientConfig) throw new Error('Client config not found.')
        const { projectId } = this.clientConfig

        try {
            const tokens = await this.getCurrentTokenData()
            const refreshToken = tokens?.refreshToken
            const accessToken = tokens?.accessToken

            // Validate refresh token before attempting refresh
            if (!this.isValidToken(refreshToken)) {
                await this.signOut('refreshToken: No valid refresh token available, signing out user')
                throw new Error('No valid refresh token available')
            }

            const response = await this.axiosInstance!({
                url: this.buildUrl(projectId, '/TOKEN/refresh'),
                method: 'post',
                data: { refreshToken, accessToken },
            })

            const tokenData = this.formatTokenData(response.data)
            await this.storeTokenData(tokenData)

            if (tokenData.firebase?.customToken && this.firebaseSignInFailed) {
                try {
                    await this.initFirebase(tokenData)
                } catch (firebaseError) {
                    console.log('[RetterSDK] refreshToken: Failed to reinitialize Firebase after token refresh:', firebaseError)
                }
            }

            return tokenData
        } catch (error: any) {
            if (this.isNetworkError(error)) {
                const authEvent = {
                    authStatus: RetterAuthStatus.CONNECTION_FAILED,
                    message: 'RefreshToken => Network error',
                }
                this.fireAuthStatusChangedEvent(authEvent)
                throw error
            }

            if (this.isAuthError(error)) {
                await this.signOut(`refreshToken: Auth error (${error.message}), signing out user`, true)
                throw error
            }

            if (this.isServerError(error)) {
                // Server error on refresh (500) - token is likely corrupt/invalid
                // Sign out user to force fresh login
                await this.signOut(`refreshToken: Server error (${error.response?.status}), signing out user`, true)
                throw error
            }

            const authEvent = {
                authStatus: RetterAuthStatus.CONNECTION_FAILED,
                message: error.message ?? 'RefreshToken => Connection Failed',
            }
            this.fireAuthStatusChangedEvent(authEvent)
            throw error
        }
    }

    public async signOut(message?: string, serviceFailed = false): Promise<void> {
        await this.sslPinningReady
        try {
            const tokenData = await this.getCurrentTokenData()

            if (tokenData) {
                const { projectId } = this.clientConfig!

                await this.axiosInstance!({
                    url: this.buildUrl(projectId, '/TOKEN/signOut'),
                    method: 'post',
                    headers: {
                        Authorization: `Bearer ${tokenData.accessToken}`,
                    },
                })
            }
        } catch (error) {
        } finally {
            await this.clearTokenData()
            await this.clearCloudObjects()
            this.fireAuthStatusChangedEvent({
                authStatus: serviceFailed ? RetterAuthStatus.SERVICE_FAILED : RetterAuthStatus.SIGNED_OUT,
                message: message || 'User signed out',
            })
        }
    }

    public async getCurrentUser(): Promise<RetterTokenPayload | undefined> {
        const tokenData = await this.getCurrentTokenData()

        return tokenData?.accessTokenDecoded
    }

    protected async storeTokenData(data: RetterTokenData): Promise<void> {
        if (typeof data === 'undefined') return
        if (!this.authStorageKey || !this.firebaseStorageKey)
            throw new Error('Token storage keys not initialized.')

        // Persist only the minimal fields needed to reconstruct everything else.
        // Keeps each SecureStore item under the 2 KB Android limit; decoded
        // payloads and ExpiresAt are derived on read.
        const accessTokenDecoded =
            data.accessTokenDecoded ??
            (data.accessToken ? jwtDecode<RetterTokenPayload>(data.accessToken) : undefined)

        const diff =
            data.diff ??
            (accessTokenDecoded?.iat
                ? accessTokenDecoded.iat - Math.floor(Date.now() / 1000)
                : 0)

        const auth = {
            accessToken: data.accessToken,
            refreshToken: data.refreshToken,
            diff,
        }

        await Promise.all([
            this.storage.setItem(this.authStorageKey, JSON.stringify(auth)),
            data.firebase
                ? this.storage.setItem(this.firebaseStorageKey, JSON.stringify(data.firebase))
                : this.storage.removeItem(this.firebaseStorageKey),
        ])
    }

    protected async clearTokenData(): Promise<void> {
        if (!this.authStorageKey || !this.firebaseStorageKey || !this.legacyTokenStorageKey)
            throw new Error('Token storage keys not initialized.')

        await Promise.all([
            this.storage.removeItem(this.authStorageKey),
            this.storage.removeItem(this.firebaseStorageKey),
            // Clean up legacy AsyncStorage blob in case migration ran on a previous launch.
            AsyncStorage.removeItem(this.legacyTokenStorageKey).catch(() => {}),
        ])
    }

    protected formatTokenData(tokenData: RetterTokenData): RetterTokenData {
        tokenData.accessTokenDecoded = jwtDecode(tokenData.accessToken)
        tokenData.refreshTokenDecoded = jwtDecode(tokenData.refreshToken)

        if (tokenData.accessTokenDecoded?.iat) {
            tokenData.diff =
                tokenData.accessTokenDecoded.iat - Math.floor(Date.now() / 1000)
        }

        return tokenData
    }

    protected async getCurrentTokenData(): Promise<
        RetterTokenData | undefined
    > {
        if (!this.authStorageKey || !this.firebaseStorageKey || !this.legacyTokenStorageKey)
        throw new Error('Token storage keys not initialized.')

        let authRaw: string | null = null
        let firebaseRaw: string | null = null
        try {
            [authRaw, firebaseRaw] = await Promise.all([
                this.storage.getItem(this.authStorageKey),
                this.storage.getItem(this.firebaseStorageKey),
            ])
        } catch (error) {
            console.log('[RetterSDK] getCurrentTokenData: Storage read failed, treating as signed out:', error)
            return undefined
        }


        if (!authRaw) {
            const migrated = await this.migrateLegacyTokenData()
            return migrated
        }

        try {
            const auth = JSON.parse(authRaw) as {
                accessToken: string
                refreshToken: string
                diff?: number
            }
            const firebase = firebaseRaw ? JSON.parse(firebaseRaw) : undefined

            return this.hydrateTokenData(auth.accessToken, auth.refreshToken, firebase, auth.diff)
        } catch (e) {
            return undefined
        }
    }

    // Reads pre-0.7.5 single-blob token from AsyncStorage and migrates it to
    // the configured (typically secure) storage. Removes the legacy entry
    // afterwards so plaintext tokens don't linger.
    private async migrateLegacyTokenData(): Promise<RetterTokenData | undefined> {
        if (!this.legacyTokenStorageKey) return undefined

        let legacyRaw: string | null = null
        try {
            legacyRaw = await AsyncStorage.getItem(this.legacyTokenStorageKey)
        } catch {
            return undefined
        }
        if (!legacyRaw) return undefined

        try {
            const legacy = JSON.parse(legacyRaw)
            if (!legacy?.accessToken || !legacy?.refreshToken) return undefined

            const hydrated = this.hydrateTokenData(
                legacy.accessToken,
                legacy.refreshToken,
                legacy.firebase,
                legacy.diff,
            )

            await this.storeTokenData(hydrated)
            await AsyncStorage.removeItem(this.legacyTokenStorageKey).catch(() => {})

            return hydrated
        } catch {
            return undefined
        }
    }

    private hydrateTokenData(
        accessToken: string,
        refreshToken: string,
        firebase: RetterTokenData['firebase'] | undefined,
        diff: number | undefined,
    ): RetterTokenData {
        const accessTokenDecoded = accessToken
            ? jwtDecode<RetterTokenPayload>(accessToken)
            : undefined
        const refreshTokenDecoded = refreshToken
            ? jwtDecode<RetterTokenPayload>(refreshToken)
            : undefined

        return {
            accessToken,
            refreshToken,
            firebase: firebase as RetterTokenData['firebase'],
            accessTokenDecoded,
            refreshTokenDecoded,
            // diff is the clock skew captured at receive-time; cannot be
            // recomputed on read. Default to 0 if missing (legacy format).
            diff: typeof diff === 'number' ? diff : 0,
            accessTokenExpiresAt: accessTokenDecoded?.exp ?? 0,
            refreshTokenExpiresAt: refreshTokenDecoded?.exp ?? 0,
        }
    }

    protected fireAuthStatusChangedEvent(event: RetterAuthChangedEvent): void {
        this.authStatusSubject.next(event)
    }

    public get authStatus(): Observable<RetterAuthChangedEvent> {
        return this.authStatusSubject
    }

    public async resetAuthState(message?: string): Promise<void> {
        try {
            await this.clearTokenData()
        } catch (error) {
            console.log('[RetterSDK] resetAuthState: clearTokenData failed', error)
        }
        try {
            await this.clearCloudObjects(false) 
        } catch (error) {
            console.log('[RetterSDK] resetAuthState: clearCloudObjects failed', error)
        }
        this.refreshTokenPromise = null
        this.firebaseSignInFailed = false
        this.fireAuthStatusChangedEvent({
            authStatus: RetterAuthStatus.SIGNED_OUT,
            message: message || 'Auth state reset',
        })
    }

    // #endregion
}
