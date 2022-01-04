//! Kubernetes compatible healh check

use axum::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;

/// Used to setup health checks for Kubernetes.
///
/// Learn more at
/// <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>
#[async_trait]
pub trait HealthCheck: Send + Sync + 'static {
    /// Corresponds to a `livenessProbe` within Kubernetes.
    ///
    /// Used to determine if the pod is live and working or if it should be killed and restarted.
    async fn is_live(&self) -> anyhow::Result<()>;

    /// Corresponds to a `readinessProbe` within Kubernetes.
    ///
    /// Used to determine if a pod is ready to receive traffic. Contrary to `is_live`, pods that
    /// aren't ready wont be restarted. This can be used to temporarily remove a pod from the load
    /// balancer while it performs some heavy task without having the pod killed.
    async fn is_ready(&self) -> anyhow::Result<()>;

    /// Combine two health checks into one.
    ///
    /// The resulting health check is live and ready if both inner health checks are.
    fn and<T>(self, rhs: T) -> And<Self, T>
    where
        Self: Sized,
        T: HealthCheck,
    {
        And { lhs: self, rhs }
    }
}

#[async_trait]
impl HealthCheck for Arc<dyn HealthCheck + Send + Sync> {
    async fn is_live(&self) -> anyhow::Result<()> {
        HealthCheck::is_live(&**self).await
    }

    async fn is_ready(&self) -> anyhow::Result<()> {
        HealthCheck::is_ready(&**self).await
    }
}

/// Two health checks combined into one.
///
/// Created with [`HealthCheck::and`].
///
/// `And` is live and ready if both inner health checks are.
#[derive(Clone, Copy, Debug)]
pub struct And<A, B> {
    lhs: A,
    rhs: B,
}

#[async_trait]
impl<A, B> HealthCheck for And<A, B>
where
    A: HealthCheck,
    B: HealthCheck,
{
    async fn is_live(&self) -> anyhow::Result<()> {
        tokio::try_join!(self.lhs.is_live(), self.rhs.is_live())?;
        Ok(())
    }

    async fn is_ready(&self) -> anyhow::Result<()> {
        tokio::try_join!(self.lhs.is_ready(), self.rhs.is_ready())?;
        Ok(())
    }
}

/// A [`HealthCheck`] that is always live and ready.
///
/// Used by [`Server::always_live_and_ready`] for servers for which health checks are not
/// necessary.
///
/// [`Server::always_live_and_ready`]: crate::Server::always_live_and_ready
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct AlwaysLiveAndReady;

#[async_trait]
impl HealthCheck for AlwaysLiveAndReady {
    async fn is_live(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn is_ready(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Sentinel value used by [`Server`] to signal that you have not yet provided a [`HealthCheck`].
///
/// [`Server`]: crate::Server
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct NoHealthCheckProvided;

/// A switch that allows you kill and restart a pod. Must be setup as a health check when booting
/// the service.
#[derive(Debug, Clone, Default)]
pub struct KillSwitch {
    killed: Arc<Mutex<Option<anyhow::Error>>>,
}

impl KillSwitch {
    /// Create a new `KillSwitch`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Flick the kill switch and restart the service.
    ///
    /// This makes [`is_live`](HealthCheck::is_live) return the given error. It does not impact
    /// [`is_ready`](HealthCheck::is_ready).
    ///
    /// `reason` allows you to add some context that will be logged.
    pub fn kill(&mut self, reason: impl Into<anyhow::Error>) {
        *self.killed.lock() = Some(reason.into());
    }
}

#[async_trait]
impl HealthCheck for KillSwitch {
    async fn is_live(&self) -> anyhow::Result<()> {
        if let Some(killed) = self.killed.lock().take() {
            Err(killed)
        } else {
            Ok(())
        }
    }

    async fn is_ready(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
