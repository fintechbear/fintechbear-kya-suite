//! A minimal, dependency-free async executor.
//!
//! The SDK is runtime-agnostic: it defines async seams but does not pull in
//! Tokio, async-std, or any other runtime. [`block_on`] drives a single future
//! to completion using only `std`, which is enough for tests and for simple
//! synchronous call sites that need to await a runtime-agnostic trait.
//!
//! The executor is unsafe-free: it relies on the stable [`core::task::Waker::noop`]
//! waker and busy-polls the future, yielding the thread between polls. The SDK's
//! async trait futures resolve by polling rather than by external wakeups, so
//! this is sufficient and introduces no runtime dependency.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

/// Drive `future` to completion on the current thread without a runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
