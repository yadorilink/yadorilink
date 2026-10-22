//! Shared port plumbing. No `async_trait`: ports are `dyn`-dispatched from
//! [`crate::application::services::ApplicationServices`], so every port
//! method returns a boxed future directly rather than relying on an
//! attribute macro that expands to the same thing less transparently.

use std::future::Future;
use std::pin::Pin;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
