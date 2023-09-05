export class Observer<T> {
    constructor(
        private onNext: (value: T) => void,
        private onError?: (error: any) => void,
        private onComplete?: () => void
    ) {}

    next(value: T): void {
        this.onNext(value)
    }

    error(error: any): void {
        if (this.onError) {
            this.onError(error)
        }
    }

    complete(): void {
        if (this.onComplete) {
            this.onComplete()
        }
    }
}

export class Observable<T> {
    private observers: Observer<T>[] = []

    constructor(private init: (observer: Observer<T>) => void) {}

    subscribe(
        onNext: (value: T) => void,
        onError?: (error: any) => void,
        onComplete?: () => void
    ) {
        const observer = new Observer(onNext, onError, onComplete)
        this.observers.push(observer)

        // Initialize the observer with initial values or events
        this.init(observer)

        return {
            unsubscribe: () => {
                const index = this.observers.indexOf(observer)
                if (index !== -1) {
                    this.observers.splice(index, 1)
                }
            },
        }
    }

    next(value: T): void {
        this.observers.forEach((observer) => {
            observer.next(value)
        })
    }

    complete(): void {
        this.observers.forEach((observer) => {
            observer.complete()
        })
    }
}

// Usage
// const observable = new Observable<string>((observer) => {
//     observer.next('Hello')
//     observer.next('World')
//     setTimeout(() => observer.next('Delayed message'), 2000)
//     observer.complete()
// })

// const subscription1 = observable.subscribe(
//     (value) => console.log(`Observer 1: ${value}`),
//     (error) => console.error(`Observer 1 Error: ${error}`),
//     () => console.log('Observer 1 completed')
// )

// const subscription2 = observable.subscribe(
//     (value) => console.log(`Observer 2: ${value}`),
//     (error) => console.error(`Observer 2 Error: ${error}`),
//     () => console.log('Observer 2 completed')
// )

// setTimeout(() => {
//     subscription1.unsubscribe()
//     subscription2.unsubscribe()
// }, 3000)
