//! Kubernetes compatible healh check

use axum::async_trait;

/// Used to setup health checks for Kubernetes.
///
/// Learn more at
/// <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>
#[async_trait]
pub trait HealthCheck: Clone + Send + Sync + 'static {
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
#[derive(Clone, Copy, Debug)]
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
