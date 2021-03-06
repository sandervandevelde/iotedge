// Copyright (c) Microsoft. All rights reserved.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use failure::Fail;
use futures::future::Either;
use futures::prelude::*;
use futures::{future, stream, Async, Future, Stream};
use hyper::service::Service;
use hyper::{Body, Chunk as HyperChunk, Request};
use log::Level;
use typed_headers::{Authorization, HeaderMapExt};
use url::Url;

use edgelet_core::{
    AuthId, Authenticator, LogOptions, ModuleRegistry, ModuleRuntime, ModuleRuntimeState,
    ModuleSpec, RuntimeOperation, SystemInfo,
};
use edgelet_docker::DockerConfig;
use edgelet_utils::{ensure_not_empty_with_context, log_failure, sanitize_dns_label};
use kube_client::{Client as KubeClient, Error as KubeClientError, TokenSource};

use crate::constants::*;
use crate::convert::{auth_to_image_pull_secret, pod_to_module};
use crate::error::{Error, ErrorKind, Result};
use crate::module::{create_module, KubeModule};

pub struct KubeModuleRuntime<T, S> {
    client: Arc<Mutex<RefCell<KubeClient<T, S>>>>,
    namespace: String,
    use_pvc: bool,
    iot_hub_hostname: String,
    device_id: String,
    edge_hostname: String,
    proxy_image: String,
    proxy_config_path: String,
    proxy_config_map_name: String,
    image_pull_policy: String,
    workload_uri: Url,
    management_uri: Url,
    device_hub_selector: String,
}

pub trait KubeRuntimeData {
    fn namespace(&self) -> &str;
    fn use_pvc(&self) -> bool;
    fn iot_hub_hostname(&self) -> &str;
    fn device_id(&self) -> &str;
    fn edge_hostname(&self) -> &str;
    fn proxy_image(&self) -> &str;
    fn proxy_config_path(&self) -> &str;
    fn proxy_config_map_name(&self) -> &str;
    fn image_pull_policy(&self) -> &str;
    fn workload_uri(&self) -> &Url;
    fn management_uri(&self) -> &Url;
}

// NOTE:
//  We are manually implementing Clone here for KubeModuleRuntime because
//  #[derive(Clone] will cause the compiler to implicitly require Clone on
//  T and S which don't really need to be Clone because we wrap it inside
//  an Arc (for the "client" field).
//
//  Requiring Clone on S in particular is problematic because we typically use
//  the kube_client::HttpClient struct for this type which does not (and cannot)
//  implement Clone.
impl<T, S> Clone for KubeModuleRuntime<T, S> {
    fn clone(&self) -> Self {
        KubeModuleRuntime {
            client: self.client.clone(),
            namespace: self.namespace.clone(),
            use_pvc: self.use_pvc,
            iot_hub_hostname: self.iot_hub_hostname.clone(),
            device_id: self.device_id.clone(),
            edge_hostname: self.edge_hostname.clone(),
            proxy_image: self.proxy_image.clone(),
            proxy_config_path: self.proxy_config_path.clone(),
            proxy_config_map_name: self.proxy_config_map_name.clone(),
            image_pull_policy: self.image_pull_policy.clone(),
            workload_uri: self.workload_uri.clone(),
            management_uri: self.management_uri.clone(),
            device_hub_selector: self.device_hub_selector.clone(),
        }
    }
}

impl<T, S> KubeRuntimeData for KubeModuleRuntime<T, S> {
    fn namespace(&self) -> &str {
        &self.namespace
    }
    fn use_pvc(&self) -> bool {
        self.use_pvc
    }
    fn iot_hub_hostname(&self) -> &str {
        &self.iot_hub_hostname
    }
    fn device_id(&self) -> &str {
        &self.device_id
    }
    fn edge_hostname(&self) -> &str {
        &self.edge_hostname
    }
    fn proxy_image(&self) -> &str {
        &self.proxy_image
    }
    fn proxy_config_path(&self) -> &str {
        &self.proxy_config_path
    }
    fn proxy_config_map_name(&self) -> &str {
        &self.proxy_config_map_name
    }
    fn image_pull_policy(&self) -> &str {
        &self.image_pull_policy
    }
    fn workload_uri(&self) -> &Url {
        &self.workload_uri
    }
    fn management_uri(&self) -> &Url {
        &self.management_uri
    }
}

impl<T, S> KubeModuleRuntime<T, S> {
    pub fn new(
        client: KubeClient<T, S>,
        namespace: String,
        use_pvc: bool,
        iot_hub_hostname: String,
        device_id: String,
        edge_hostname: String,
        proxy_image: String,
        proxy_config_path: String,
        proxy_config_map_name: String,
        image_pull_policy: String,
        workload_uri: Url,
        management_uri: Url,
    ) -> Result<Self> {
        ensure_not_empty_with_context(&namespace, || {
            ErrorKind::InvalidRunTimeParameter(String::from("namespace"), namespace.clone())
        })?;
        ensure_not_empty_with_context(&iot_hub_hostname, || {
            ErrorKind::InvalidRunTimeParameter(
                String::from("iot_hub_hostname"),
                iot_hub_hostname.clone(),
            )
        })?;
        ensure_not_empty_with_context(&device_id, || {
            ErrorKind::InvalidRunTimeParameter(String::from("device_id"), device_id.clone())
        })?;
        ensure_not_empty_with_context(&edge_hostname, || {
            ErrorKind::InvalidRunTimeParameter(String::from("edge_hostname"), edge_hostname.clone())
        })?;
        ensure_not_empty_with_context(&proxy_image, || {
            ErrorKind::InvalidRunTimeParameter(String::from("proxy_image"), proxy_image.clone())
        })?;
        ensure_not_empty_with_context(&proxy_config_path, || {
            ErrorKind::InvalidRunTimeParameter(
                String::from("proxy_config_path"),
                proxy_config_path.clone(),
            )
        })?;
        ensure_not_empty_with_context(&proxy_config_map_name, || {
            ErrorKind::InvalidRunTimeParameter(
                String::from("proxy_config_map_name"),
                proxy_config_map_name.clone(),
            )
        })?;
        ensure_not_empty_with_context(&image_pull_policy, || {
            ErrorKind::InvalidRunTimeParameter(
                String::from("image_pull_policy"),
                image_pull_policy.clone(),
            )
        })?;
        let device_hub_selector = format!(
            "{}={},{}={}",
            EDGE_DEVICE_LABEL,
            sanitize_dns_label(&device_id),
            EDGE_HUBNAME_LABEL,
            sanitize_dns_label(&iot_hub_hostname)
        );

        Ok(KubeModuleRuntime {
            client: Arc::new(Mutex::new(RefCell::new(client))),
            namespace,
            use_pvc,
            iot_hub_hostname,
            device_id,
            edge_hostname,
            proxy_image,
            proxy_config_path,
            proxy_config_map_name,
            image_pull_policy,
            workload_uri,
            management_uri,
            device_hub_selector,
        })
    }

    pub(crate) fn client(&self) -> Arc<Mutex<RefCell<KubeClient<T, S>>>> {
        self.client.clone()
    }
}

impl<T, S> ModuleRegistry for KubeModuleRuntime<T, S>
where
    T: TokenSource + Send + 'static,
    S: Service + Send + 'static,
    S::ReqBody: From<Vec<u8>>,
    S::ResBody: Stream,
    Body: From<S::ResBody>,
    S::Error: Into<KubeClientError>,
    S::Future: Send,
{
    type Error = Error;
    type PullFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type RemoveFuture = Box<dyn Future<Item = (), Error = Self::Error>>;
    type Config = DockerConfig;

    fn pull(&self, config: &Self::Config) -> Self::PullFuture {
        // Find and generate image pull secrets.
        if let Some(auth) = config.auth() {
            // Have authorization for this module spec, create this if it doesn't exist.
            let fut = auth_to_image_pull_secret(self.namespace(), auth)
                .map_err(Error::from)
                .map(|(secret_name, pull_secret)| {
                    let client_copy = self.client.clone();
                    let namespace_copy = self.namespace().to_owned();
                    self.client
                        .lock()
                        .expect("Unexpected lock error")
                        .borrow_mut()
                        .list_secrets(self.namespace(), Some(secret_name.as_str()))
                        .map_err(Error::from)
                        .and_then(move |secrets| {
                            if let Some(current_secret) = secrets.items.into_iter().find(|secret| {
                                secret.metadata.as_ref().map_or(false, |meta| {
                                    meta.name.as_ref().map_or(false, |n| *n == secret_name)
                                })
                            }) {
                                if current_secret == pull_secret {
                                    Either::A(Either::A(future::ok(())))
                                } else {
                                    let f = client_copy
                                        .lock()
                                        .expect("Unexpected lock error")
                                        .borrow_mut()
                                        .replace_secret(
                                            namespace_copy.as_str(),
                                            secret_name.as_str(),
                                            &pull_secret,
                                        )
                                        .map_err(Error::from)
                                        .map(|_| ());

                                    Either::A(Either::B(f))
                                }
                            } else {
                                let f = client_copy
                                    .lock()
                                    .expect("Unexpected lock error")
                                    .borrow_mut()
                                    .create_secret(namespace_copy.as_str(), &pull_secret)
                                    .map_err(Error::from)
                                    .map(|_| ());

                                Either::B(f)
                            }
                        })
                })
                .into_future()
                .flatten();

            Box::new(fut)
        } else {
            Box::new(future::ok(()))
        }
    }

    fn remove(&self, _: &str) -> Self::RemoveFuture {
        Box::new(future::ok(()))
    }
}

impl<T, S> ModuleRuntime for KubeModuleRuntime<T, S>
where
    T: TokenSource + Send + 'static,
    S: Service + Send + 'static,
    S::ReqBody: From<Vec<u8>>,
    S::ResBody: Stream,
    Body: From<S::ResBody>,
    S::Error: Into<KubeClientError>,
    S::Future: Send,
{
    type Error = Error;
    type Config = DockerConfig;
    type Module = KubeModule;
    type ModuleRegistry = Self;
    type Chunk = Chunk;
    type Logs = Logs;

    type CreateFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type GetFuture =
        Box<dyn Future<Item = (Self::Module, ModuleRuntimeState), Error = Self::Error> + Send>;
    type InitFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type ListFuture = Box<dyn Future<Item = Vec<Self::Module>, Error = Self::Error> + Send>;
    type ListWithDetailsStream =
        Box<dyn Stream<Item = (Self::Module, ModuleRuntimeState), Error = Self::Error> + Send>;
    type LogsFuture = Box<dyn Future<Item = Self::Logs, Error = Self::Error> + Send>;
    type RemoveFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type RestartFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type StartFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type StopFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;
    type SystemInfoFuture = Box<dyn Future<Item = SystemInfo, Error = Self::Error> + Send>;
    type RemoveAllFuture = Box<dyn Future<Item = (), Error = Self::Error> + Send>;

    fn init(&self) -> Self::InitFuture {
        Box::new(future::ok(()))
    }

    fn create(&self, module: ModuleSpec<Self::Config>) -> Self::CreateFuture {
        Box::new(create_module(self, &module))
    }

    fn get(&self, _id: &str) -> Self::GetFuture {
        unimplemented!()
    }

    fn start(&self, _id: &str) -> Self::StartFuture {
        Box::new(future::ok(()))
    }

    fn stop(&self, _id: &str, _wait_before_kill: Option<Duration>) -> Self::StopFuture {
        Box::new(future::ok(()))
    }

    fn restart(&self, _id: &str) -> Self::RestartFuture {
        Box::new(future::ok(()))
    }

    fn remove(&self, _id: &str) -> Self::RemoveFuture {
        Box::new(future::ok(()))
    }

    fn system_info(&self) -> Self::SystemInfoFuture {
        // TODO: Implement this.
        Box::new(future::ok(SystemInfo::new(
            "linux".to_string(),
            "x86_64".to_string(),
        )))
    }

    fn list(&self) -> Self::ListFuture {
        let result = self
            .client
            .lock()
            .expect("Unexpected lock error")
            .borrow_mut()
            .list_pods(&self.namespace, Some(&self.device_hub_selector))
            .map_err(Error::from)
            .and_then(|pods| {
                pods.items
                    .into_iter()
                    .filter_map(|pod| pod_to_module(&pod))
                    .try_fold(vec![], |mut modules, module_result| {
                        module_result.map(|module| {
                            modules.push(module);
                            modules
                        })
                    })
                    .into_future()
            });

        Box::new(result)
    }

    fn list_with_details(&self) -> Self::ListWithDetailsStream {
        Box::new(stream::empty())
    }

    fn logs(&self, _id: &str, _options: &LogOptions) -> Self::LogsFuture {
        Box::new(future::ok(Logs("".to_string(), Body::empty())))
    }

    fn registry(&self) -> &Self::ModuleRegistry {
        self
    }

    fn remove_all(&self) -> Self::RemoveAllFuture {
        Box::new(future::ok(()))
    }
}

impl<T, S> Authenticator for KubeModuleRuntime<T, S>
where
    T: TokenSource + 'static,
    S: Service + Send + 'static,
    S::ReqBody: From<Vec<u8>>,
    S::ResBody: Stream,
    Body: From<S::ResBody>,
    S::Error: Into<KubeClientError>,
    S::Future: Send,
{
    type Error = Error;
    type Request = Request<Body>;
    type AuthenticateFuture = Box<dyn Future<Item = AuthId, Error = Self::Error> + Send>;

    fn authenticate(&self, req: &Self::Request) -> Self::AuthenticateFuture {
        let fut = req
            .headers()
            .typed_get::<Authorization>()
            .map(|auth| {
                auth.and_then(|auth| {
                    auth.as_bearer().map(|token| {
                        let fut = self
                            .client
                            .lock()
                            .expect("Unexpected lock error")
                            .borrow_mut()
                            .token_review(self.namespace(), token.as_str())
                            .map_err(|err| {
                                log_failure(Level::Warn, &err);
                                Error::from(err)
                            })
                            .map(|token_review| {
                                token_review
                                    .status
                                    .as_ref()
                                    .filter(|status| status.authenticated.filter(|x| *x).is_some())
                                    .and_then(|status| {
                                        status.user.as_ref().and_then(|user| user.username.clone())
                                    })
                                    .map_or(AuthId::None, |name| AuthId::Value(name.into()))
                            });

                        Either::A(fut)
                    })
                })
                .unwrap_or_else(|| Either::B(future::ok(AuthId::None)))
            })
            .map_err(Error::from)
            .into_future()
            .flatten();

        Box::new(fut)
    }
}

#[derive(Debug)]
pub struct Logs(String, Body);

impl Stream for Logs {
    type Item = Chunk;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.1.poll() {
            Ok(Async::Ready(chunk)) => Ok(Async::Ready(chunk.map(Chunk))),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => Err(Error::from(err.context(ErrorKind::RuntimeOperation(
                RuntimeOperation::GetModuleLogs(self.0.clone()),
            )))),
        }
    }
}

impl From<Logs> for Body {
    fn from(logs: Logs) -> Self {
        logs.1
    }
}

#[derive(Debug, Default)]
pub struct Chunk(HyperChunk);

impl IntoIterator for Chunk {
    type Item = u8;
    type IntoIter = <HyperChunk as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Extend<u8> for Chunk {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u8>,
    {
        self.0.extend(iter)
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use native_tls::TlsConnector;
    use url::Url;

    use kube_client::{Client as KubeClient, Config, Error, TokenSource};

    use crate::runtime::KubeModuleRuntime;

    fn get_config() -> Config<TestTokenSource> {
        Config::new(
            Url::parse("https://localhost:443").unwrap(),
            "/api".to_string(),
            TestTokenSource,
            TlsConnector::new().unwrap(),
        )
    }

    #[test]
    fn runtime_new() {
        let namespace = String::from("my-namespace");
        let iot_hub_hostname = String::from("iothostname");
        let device_id = String::from("my_device_id");
        let edge_hostname = String::from("edge-hostname");
        let proxy_image = String::from("proxy-image");
        let proxy_config_path = String::from("proxy-confg-path");
        let proxy_config_map_name = String::from("config-volume");
        let image_pull_policy = String::from("OnCreate");
        let workload_uri = Url::from_str("http://localhost:35000").unwrap();
        let management_uri = Url::from_str("http://localhost:35001").unwrap();

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            String::default(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );

        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            String::default(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            String::default(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            String::default(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            String::default(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            String::default(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            String::default(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            String::default(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_err());

        let result = KubeModuleRuntime::new(
            KubeClient::new(get_config()),
            namespace.clone(),
            true,
            iot_hub_hostname.clone(),
            device_id.clone(),
            edge_hostname.clone(),
            proxy_image.clone(),
            proxy_config_path.clone(),
            proxy_config_map_name.clone(),
            image_pull_policy.clone(),
            workload_uri.clone(),
            management_uri.clone(),
        );
        assert!(result.is_ok());
    }

    #[derive(Clone)]
    struct TestTokenSource;

    impl TokenSource for TestTokenSource {
        type Error = Error;

        fn get(&self) -> kube_client::error::Result<Option<String>> {
            Ok(None)
        }
    }
}
