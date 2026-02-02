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
    RetterTokenData,
    RetterTokenPayload,
} from './types'
import jwtDecode from 'jwt-decode'
import { getFirestore, doc, onSnapshot } from '@react-native-firebase/firestore'
import { getAuth, signInWithCustomToken, signOut } from '@react-native-firebase/auth'
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'
// import { Agent } from 'https'
import { base64Encode, getInstallationId, sort } from './helpers'

export * from './types'

const DEFAULT_RETRY_DELAY = 50 // in ms
const DEFAULT_RETRY_COUNT = 3
const DEFAULT_RETRY_RATE = 1.5

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

    private tokenStorageKey?: string

    private authStatusSubject: Observable<RetterAuthChangedEvent>

    private refreshTokenPromise: Promise<any> | null = null

    private firebaseSignInFailed = false;

    private sslPinningEnabled: boolean = true

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

        this.tokenStorageKey = `RIO_TOKENS_KEY.${config.projectId}`
        if (!this.clientConfig.region)
            this.clientConfig.region = RetterRegion.euWest1

        if (!this.clientConfig.retryConfig) this.clientConfig.retryConfig = {}
        if (!this.clientConfig.retryConfig.delay)
            this.clientConfig.retryConfig.delay = DEFAULT_RETRY_DELAY
        if (!this.clientConfig.retryConfig.count)
            this.clientConfig.retryConfig.count = DEFAULT_RETRY_COUNT
        if (!this.clientConfig.retryConfig.rate)
            this.clientConfig.retryConfig.rate = DEFAULT_RETRY_RATE


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

        if (this.sslPinningEnabled === false) {
            // axiosConfig.httpsAgent = new Agent({ rejectUnauthorized: false })
        }

        this.axiosInstance! = axios.create(axiosConfig)
    }

    protected async makeAPIRequest<T>(
        action: RetterActions,
        data: RetterCloudObjectConfig,
        retryCount: number = 0
    ): Promise<RetterCallResponse<T>> {
        try {
            const endpoint = this.generateEndpoint(action, data)
            const tokens = await this.getCurrentTokenData()

            const now = Math.floor(Date.now() / 1000)
            const safeNow = now + 30 + (tokens?.diff ?? 0) // add server time diff
            const accessTokenDecoded = tokens?.accessTokenDecoded

            if (accessTokenDecoded && accessTokenDecoded.exp < safeNow) {
                // Check if refresh token is also expired before attempting refresh
                const refreshTokenDecoded = tokens?.refreshTokenDecoded
                if (refreshTokenDecoded && refreshTokenDecoded.exp < safeNow) {
                    console.log('[RetterSDK] makeAPIRequest: Both access and refresh tokens expired, signing out')
                    await this.signOut('Session expired')
                    this.fireAuthStatusChangedEvent({
                        authStatus: RetterAuthStatus.SIGNED_OUT,
                        message: 'Session expired - please login again',
                    })
                    throw new Error('Session expired - please login again')
                }

                // If there's already a refresh in progress, wait for it
                if (this.refreshTokenPromise) {
                    try {
                        const newTokenData = await this.refreshTokenPromise
                        if (!newTokenData) {
                            this.fireAuthStatusChangedEvent({
                                authStatus: RetterAuthStatus.SIGNED_OUT,
                                message: 'Already have refreshTokenPromise => tokenData is undefined',
                            })
                            throw new Error('Access token is undefined.')
                        }
                        const newData = { ...data }
                        newData.headers = {
                            ...newData.headers,
                            Authorization: `Bearer ${newTokenData}`,
                        }

                        return await this.executeRequest(endpoint, newData)
                    } catch (error) {
                        throw error
                    }
                }

                // Create a new refresh promise - cleanup happens AFTER await completes
                const refreshPromise = this.refreshToken()
                    .then((response) => response.accessToken)

                this.refreshTokenPromise = refreshPromise

                try {
                    const newToken = await refreshPromise
                    // Cleanup after successful await - this ensures other waiters get the value first
                    this.refreshTokenPromise = null

                    if (!newToken) {
                        this.fireAuthStatusChangedEvent({
                            authStatus: RetterAuthStatus.SIGNED_OUT,
                            message: 'First time refreshTokenPromise => tokenData is undefined',
                        })
                        throw new Error('Access token is undefined.')
                    }
                    const newData = { ...data }
                    newData.headers = {
                        ...newData.headers,
                        Authorization: `Bearer ${newToken}`,
                    }
                    return await this.executeRequest(endpoint, newData)
                } catch (error) {
                    // Cleanup on error as well
                    this.refreshTokenPromise = null
                    throw error
                }
            } else {
                const newData = { ...data }
                if (this.isValidToken(tokens?.accessToken)) {
                    newData.headers = {
                        ...newData.headers,
                        Authorization: `Bearer ${tokens!.accessToken}`,
                    }
                } else {
                    this.fireAuthStatusChangedEvent({
                        authStatus: RetterAuthStatus.SIGNED_OUT,
                        message: 'Access token is undefined',
                    })
                }
                return await this.executeRequest(endpoint, newData)
            }
        } catch (error) {
            if (this.isRetryableError(error) && retryCount < 3) {
                const delay = Math.min(1000 * Math.pow(2, retryCount), 5000) // Exponential backoff, max 5s
                await new Promise(resolve => setTimeout(resolve, delay))
                return this.makeAPIRequest(action, data, retryCount + 1)
            }
            throw error
        }

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
                    // if (
                    //     error.response &&
                    //     error.response.status === 403 &&
                    //     error.response.data &&
                    //     error.response.data.code === 'ACCESS_DENIED'
                    // ) {
                    //     this.signOut()
                    // }
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
            const listeners = Object.values(this.listeners)
            if (listeners.length > 0) {
                listeners.map((i) => i())

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
        const tokens = await this.getCurrentTokenData()
        if (tokens) {
            try {
                const firebaseResult = await this.initFirebase(tokens)
                if (firebaseResult instanceof Error) {
                    // console.warn('[RetterSDK] initAuth: Firebase initialization failed, signing out user')
                }

                this.fireAuthStatusChangedEvent({
                    authStatus: RetterAuthStatus.SIGNED_IN,
                    uid: tokens.accessTokenDecoded?.userId,
                    identity: tokens.accessTokenDecoded?.identity,
                })
            } catch (error) {
                console.error('[RetterSDK] initAuth: Auth initialization error:', error)
            }
        } else {
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_OUT,
                message: 'First Init access token is undefined',
            })
        }
    }

    public async authenticateWithCustomToken(
        token: string
    ): Promise<RetterAuthChangedEvent> {
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
        if (!this.clientConfig) throw new Error('Client config not found.')
        const { projectId } = this.clientConfig

        try {
            const tokens = await this.getCurrentTokenData()
            const refreshToken = tokens?.refreshToken
            const accessToken = tokens?.accessToken

            // Validate refresh token before attempting refresh
            if (!this.isValidToken(refreshToken)) {
                console.log('[RetterSDK] refreshToken: No valid refresh token available')
                await this.signOut('No valid refresh token')
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
                    message: 'Network error, retrying...',
                }
                this.fireAuthStatusChangedEvent(authEvent)
                throw error
            }

            if (this.isAuthError(error)) {
                await this.signOut(error.message)
                throw error
            }

            if (this.isServerError(error)) {
                // Server error on refresh (500) - token is likely corrupt/invalid
                // Sign out user to force fresh login
                console.log(`[RetterSDK] refreshToken: Server error (${error.response?.status}), signing out user`)
                await this.signOut('Token refresh failed - server error')
                throw error
            }

            const authEvent = {
                authStatus: RetterAuthStatus.CONNECTION_FAILED,
                message: error.message ?? 'Connection Failed',
            }
            this.fireAuthStatusChangedEvent(authEvent)
            throw error
        }
    }

    public async signOut(message?: string): Promise<void> {
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
                authStatus: RetterAuthStatus.SIGNED_OUT,
                message: 'Signed out function called',
            })
        }
    }

    public async getCurrentUser(): Promise<RetterTokenPayload | undefined> {
        const tokenData = await this.getCurrentTokenData()

        return tokenData?.accessTokenDecoded
    }

    protected async storeTokenData(data: RetterTokenData): Promise<void> {
        if (typeof data === 'undefined') return

        // Ensure decoded tokens and diff are stored for consistent reads
        if (!data.accessTokenDecoded && data.accessToken) {
            data.accessTokenDecoded = jwtDecode(data.accessToken)
        }
        if (!data.refreshTokenDecoded && data.refreshToken) {
            data.refreshTokenDecoded = jwtDecode(data.refreshToken)
        }
        if (data.accessTokenDecoded?.iat && data.diff === undefined) {
            data.diff = data.accessTokenDecoded.iat - Math.floor(Date.now() / 1000)
        }

        await AsyncStorage.setItem(this.tokenStorageKey!, JSON.stringify(data))
    }

    protected async clearTokenData(): Promise<void> {
        await AsyncStorage.removeItem(this.tokenStorageKey!)
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
        if (!this.tokenStorageKey)
            throw new Error('Token storage key not found.')
        const item = await AsyncStorage.getItem(this.tokenStorageKey)
        if (!item) return undefined

        try {
            const data = JSON.parse(item)

            // Decode tokens if not already decoded
            if (!data.accessTokenDecoded && data.accessToken) {
                data.accessTokenDecoded = jwtDecode(data.accessToken)
            }
            if (!data.refreshTokenDecoded && data.refreshToken) {
                data.refreshTokenDecoded = jwtDecode(data.refreshToken)
            }

            // IMPORTANT: diff should ONLY be calculated when token is received from server
            // (in formatTokenData/storeTokenData), NOT when reading from storage.
            // If diff is missing from storage (old format), default to 0 for safety.
            // This prevents incorrect time calculations that could cause jwt expired errors.
            if (data.diff === undefined) {
                data.diff = 0
            }

            return data
        } catch (e) {
            return undefined
        }
    }

    protected fireAuthStatusChangedEvent(event: RetterAuthChangedEvent): void {
        this.authStatusSubject.next(event)
    }

    public get authStatus(): Observable<RetterAuthChangedEvent> {
        return this.authStatusSubject
    }

    // #endregion
}
