//! Standard library unstable features

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

// core::task::ready! should be stablized soonly
macro_rules! ready {
    ($e:expr) => {
        match $e {
            Poll::Ready(t) => t,
            Poll::Pending => {
                return Poll::Pending;
            }
        }
    };
}

pub(crate) use ready;

pub fn poll_fn<T, F>(f: F) -> PollFn<F>
where
    F: FnMut(&mut Context<'_>) -> Poll<T>,
{
    PollFn { f }
}

/// A Future that wraps a function returning [`Poll`].
pub struct PollFn<F> {
    f: F,
}

impl<F> Unpin for PollFn<F> {}

impl<T, F> Future for PollFn<F>
where
    F: FnMut(&mut Context<'_>) -> Poll<T>,
{
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        (self.f)(cx)
    }
}
