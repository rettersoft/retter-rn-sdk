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
import { FirebaseApp, initializeApp } from 'firebase/app'
import { doc, Firestore, onSnapshot } from 'firebase/firestore'
import { initializeFirestore } from 'firebase/firestore'
import { Auth, getAuth, signInWithCustomToken, signOut } from 'firebase/auth'
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'
import { Agent } from 'https'
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

    private firebase?: FirebaseApp

    private firestore?: Firestore

    private firebaseAuth?: Auth

    private refreshTokenPromise: Promise<any> | null = null

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

        this.authStatusSubject = new Observable<RetterAuthChangedEvent>(
            () => {}
        )

        this.authStatus.setOnFirstSubscription(() => {
            this.initAuth()
        })

        this.createAxiosInstance()
        this.initAuth()
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
            axiosConfig.httpsAgent = new Agent({ rejectUnauthorized: false })
        }

        this.axiosInstance! = axios.create(axiosConfig)
    }

    protected async makeAPIRequest<T>(
        action: RetterActions,
        data: RetterCloudObjectConfig
    ): Promise<RetterCallResponse<T>> {
        const endpoint = this.generateEndpoint(action, data)
        const tokens = await this.getCurrentTokenData()

        const now = Math.floor(Date.now() / 1000)
        const safeNow = now + 30 + (tokens?.diff ?? 0) // add server time diff
        const accessTokenDecoded = tokens?.accessTokenDecoded

        if (accessTokenDecoded && accessTokenDecoded.exp < safeNow) {
            if (this.refreshTokenPromise) {
                try {
                    const newTokenData = await this.refreshTokenPromise
                    const newData = { ...data }
                    newData.headers = {
                        ...newData.headers,
                        Authorization: `Bearer ${newTokenData.accessToken}`,
                    }

                    return await this.executeRequest(endpoint, newData)
                } catch (error) {
                    throw error
                }
            }

            this.refreshTokenPromise = (async () => {
                try {
                    const response = await this.refreshToken()
                    this.refreshTokenPromise = null
                    return response.accessToken
                } catch (error) {
                    this.refreshTokenPromise = null
                    throw error
                }
            })()

            try {
                const newToken = await this.refreshTokenPromise
                const newData = { ...data }
                newData.headers = {
                    ...newData.headers,
                    Authorization: `Bearer ${newToken}`,
                }
                return await this.executeRequest(endpoint, newData)
            } catch (error) {
                throw error
            }
        } else {
            const newData = { ...data }
            if (tokens?.accessToken) {
                newData.headers = {
                    ...newData.headers,
                    Authorization: `Bearer ${tokens.accessToken}`,
                }
            }
            return await this.executeRequest(endpoint, newData)
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
            : `${projectId}.${
                  RetterRegions.find(
                      (region) => region.id === this.clientConfig?.region
                  )?.url
              }`

        return `https://${prefix}/${this.clientConfig?.projectId}${path}`
    }

    // #endregion

    // #region Firebase
    protected async initFirebase(tokenData?: RetterTokenData) {
        const firebaseConfig = tokenData?.firebase
        if (!firebaseConfig || this.firebase) return

        this.firebase = initializeApp(
            {
                apiKey: firebaseConfig.apiKey,
                authDomain: firebaseConfig.projectId + '.firebaseapp.com',
                projectId: firebaseConfig.projectId,
            },
            this.clientConfig!.projectId
        )

        this.firestore = initializeFirestore(this.firebase!, {
            experimentalForceLongPolling: true,
        })
        this.firebaseAuth = getAuth(this.firebase!)

        await signInWithCustomToken(
            this.firebaseAuth!,
            firebaseConfig.customToken
        ).catch(() => {})
    }

    protected clearFirebase() {
        this.firebase = undefined
        this.firestore = undefined
        this.firebaseAuth = undefined
    }

    protected getFirebaseListener(
        queue: any,
        collection: string,
        documentId: string
    ): () => void {
        const document = doc(this.firestore!, collection, documentId)

        return onSnapshot(document, (doc) => {
            const data = Object.assign({}, doc.data())
            for (const key of Object.keys(data)) {
                if (key.startsWith('__')) delete data[key]
            }
            queue.next(data)
        })
    }

    protected async getFirebaseState(config: RetterCloudObjectConfig) {
        if (!this.clientConfig) throw new Error('Client config not found.')

        const { projectId } = this.clientConfig

        const user = await this.getCurrentUser()

        const unsubscribers: (() => void)[] = []

        const observables = {
            role: new Observable<any>(() => {}),
            user: new Observable<any>(() => {}),
            public: new Observable<any>(() => {}),
        }

        const listenerPrefix = `${projectId}_${config.classId}_${config.instanceId}`

        const state = {
            role: {
                observable: observables.role,
                subscribe: (callback: (data: any) => void) => {
                    if (!this.listeners[`${listenerPrefix}_role`]) {
                        const listener = this.getFirebaseListener(
                            observables.role,
                            `/projects/${projectId}/classes/${config.classId}/instances/${config.instanceId}/roleState`,
                            user!.identity!
                        )
                        this.listeners[`${listenerPrefix}_role`] = listener
                    }

                    return observables.role.subscribe(callback)
                },
            },
            user: {
                observable: observables.user,
                subscribe: (callback: (data: any) => void) => {
                    if (!this.listeners[`${listenerPrefix}_user`]) {
                        const listener = this.getFirebaseListener(
                            observables.user,
                            `/projects/${projectId}/classes/${config.classId}/instances/${config.instanceId}/userState`,
                            user!.userId!
                        )
                        this.listeners[`${listenerPrefix}_user`] = listener
                    }

                    return observables.user.subscribe(callback)
                },
            },
            public: {
                observable: observables.public,
                subscribe: (callback: (data: any) => void) => {
                    if (!this.listeners[`${listenerPrefix}_public`]) {
                        const listener = this.getFirebaseListener(
                            observables.public,
                            `/projects/${projectId}/classes/${config.classId}/instances`,
                            config.instanceId!
                        )
                        this.listeners[`${listenerPrefix}_public`] = listener
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

        const { state } = await this.getFirebaseState(config)

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

    protected async clearCloudObjects() {
        // clear listeners
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

        if (this.firebaseAuth) await signOut(this.firebaseAuth!)
        this.clearFirebase()
    }

    // #endregion

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
            await this.initFirebase(tokens)
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_IN,
                uid: tokens.accessTokenDecoded?.userId,
                identity: tokens.accessTokenDecoded?.identity,
            })
        } else {
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_OUT,
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

        this.clearFirebase()
        this.clearCloudObjects()
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

            const response = await this.axiosInstance!({
                url: this.buildUrl(projectId, '/TOKEN/refresh'),
                method: 'post',
                data: { refreshToken },
            })

            const tokenData = this.formatTokenData(response.data)
            await this.storeTokenData(tokenData)
            return tokenData
        } catch (error: any) {
            const isNetworkError = error.message === 'Network Error'
            if (!isNetworkError) await this.signOut()

            throw error
        }
    }

    public async signOut(): Promise<void> {
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
            this.clearFirebase()
            await this.clearTokenData()
            await this.clearCloudObjects()
            this.fireAuthStatusChangedEvent({
                authStatus: RetterAuthStatus.SIGNED_OUT,
            })
        }
    }

    public async getCurrentUser(): Promise<RetterTokenPayload | undefined> {
        const tokenData = await this.getCurrentTokenData()

        return tokenData?.accessTokenDecoded
    }

    protected async storeTokenData(data: RetterTokenData): Promise<void> {
        if (typeof data === 'undefined') return
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
            if (data.accessTokenDecoded && data.refreshTokenDecoded) return data
            data.accessTokenDecoded = jwtDecode(data.accessToken)
            data.refreshTokenDecoded = jwtDecode(data.refreshToken)

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
