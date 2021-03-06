// Copyright (c) Microsoft. All rights reserved.

use std::fmt;
use std::fmt::Display;
#[cfg(windows)]
use std::sync::Mutex;

use edgelet_core::Error as CoreError;
use edgelet_core::ErrorKind as CoreErrorKind;
use edgelet_http::Error as HttpError;
use edgelet_http::ErrorKind as HttpErrorKind;
use iothubservice::Error as HubServiceError;

use failure::{Backtrace, Context, Fail};
#[cfg(windows)]
use windows_service::Error as WindowsServiceError;

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Clone, Debug, Fail, PartialEq)]
pub enum ErrorKind {
    #[fail(display = "The symmetric key string could not be activated")]
    ActivateSymmetricKey,

    #[fail(display = "The certificate management expiration timer encountered a failure.")]
    CertificateExpirationManagement,

    #[fail(display = "The daemon could not start up successfully: {}", _0)]
    Initialize(InitializeErrorReason),

    #[fail(display = "Invalid signed token was provided.")]
    InvalidSignedToken,

    #[fail(display = "The management service encountered an error")]
    ManagementService,

    #[fail(display = "The symmetric key string is malformed")]
    SymmetricKeyMalformed,

    #[cfg(windows)]
    #[fail(display = "The daemon encountered an error while updating its Windows Service state")]
    UpdateWindowsServiceState,

    #[fail(display = "The watchdog encountered an error")]
    Watchdog,

    #[fail(display = "The workload service encountered an error")]
    WorkloadService,
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        let fail: &dyn Fail = &error;
        let mut error_kind = ErrorKind::Watchdog;

        for cause in fail.iter_causes() {
            if let Some(service_err) = cause.downcast_ref::<HubServiceError>() {
                let hub_failure: &dyn Fail = service_err;

                for cause in hub_failure.iter_causes() {
                    if let Some(err) = cause.downcast_ref::<HttpError>() {
                        match HttpError::kind(err) {
                            HttpErrorKind::Http => {
                                error_kind =
                                    ErrorKind::Initialize(InitializeErrorReason::InvalidHubConfig);
                            }
                            HttpErrorKind::HttpWithErrorResponse(code, _message) => {
                                if code.as_u16() == 401 {
                                    error_kind = ErrorKind::InvalidSignedToken;
                                }
                            }
                            _ => {}
                        };

                        break;
                    }
                }

                break;
            }
        }

        let error_kind_result = match error.kind() {
            CoreErrorKind::EdgeRuntimeIdentityNotFound => {
                ErrorKind::Initialize(InitializeErrorReason::InvalidDeviceConfig)
            }
            _ => error_kind,
        };

        Error::from(error.context(error_kind_result))
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Error { inner }
    }
}

impl From<&ErrorKind> for i32 {
    fn from(err: &ErrorKind) -> Self {
        match err {
            // Using 150 as the starting base for custom IoT edge error codes so as to avoid
            // collisions with -
            // 1. The standard error codes defined by the BSD ecosystem
            // (https://www.freebsd.org/cgi/man.cgi?query=sysexits&apropos=0&sektion=0&manpath=FreeBSD+11.2-stable&arch=default&format=html)
            // that is recommended by the Rust docs
            // (https://rust-lang-nursery.github.io/cli-wg/in-depth/exit-code.html)
            // 2. Bash scripting exit codes with special meanings
            // (http://www.tldp.org/LDP/abs/html/exitcodes.html)
            ErrorKind::Initialize(InitializeErrorReason::InvalidDeviceConfig) => 150,
            ErrorKind::Initialize(InitializeErrorReason::InvalidHubConfig) => 151,
            ErrorKind::InvalidSignedToken => 152,
            ErrorKind::Initialize(InitializeErrorReason::NotConfigured) => 153,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InitializeErrorReason {
    CreateCertificateManager,
    CreateMasterEncryptionKey,
    CreateSettingsDirectory,
    CreateTlsCertificate,
    DestroyWorkloadCa,
    DeviceClient,
    DpsProvisioningClient,
    EdgeRuntime,
    ExternalProvisioningClient,
    Hsm,
    HttpClient,
    InvalidDeviceConfig,
    InvalidHubConfig,
    InvalidProxyUri,
    InvalidSocketUri,
    IssuerCAExpiration,
    LoadSettings,
    ManagementService,
    ManualProvisioningClient,
    ModuleRuntime,
    NotConfigured,
    PrepareWorkloadCa,
    #[cfg(windows)]
    RegisterWindowsService,
    RemoveExistingModules,
    SaveSettings,
    #[cfg(windows)]
    StartWindowsService,
    Tokio,
    WorkloadService,
}

impl fmt::Display for InitializeErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitializeErrorReason::CreateCertificateManager => {
                write!(f, "Could not create the certificate manager.")
            }

            InitializeErrorReason::CreateMasterEncryptionKey => {
                write!(f, "Could not create master encryption key")
            }

            InitializeErrorReason::CreateSettingsDirectory => {
                write!(f, "Could not create settings directory")
            }

            InitializeErrorReason::CreateTlsCertificate => {
                write!(f, "Could not create TLS certificate")
            }

            InitializeErrorReason::DestroyWorkloadCa => {
                write!(f, "Could not destroy workload CA certificate")
            }

            InitializeErrorReason::DeviceClient => write!(f, "Could not initialize device client"),

            InitializeErrorReason::DpsProvisioningClient => {
                write!(f, "Could not initialize DPS provisioning client")
            }

            InitializeErrorReason::EdgeRuntime => write!(f, "Could not initialize edge runtime"),

            InitializeErrorReason::ExternalProvisioningClient => {
                write!(f, "Could not initialize external provisioning client")
            }

            InitializeErrorReason::Hsm => write!(f, "Could not initialize HSM"),

            InitializeErrorReason::HttpClient => write!(f, "Could not initialize HTTP client"),

            InitializeErrorReason::InvalidDeviceConfig => {
                write!(f, "Invalid device configuration was provided")
            }

            InitializeErrorReason::InvalidHubConfig => {
                write!(f, "Invalid IoT hub configuration was provided")
            }

            InitializeErrorReason::InvalidProxyUri => write!(f, "Invalid proxy URI"),

            InitializeErrorReason::InvalidSocketUri => write!(f, "Invalid socket URI"),

            InitializeErrorReason::IssuerCAExpiration => {
                write!(f, "Edge device CA has expired or is near expiration")
            }

            InitializeErrorReason::LoadSettings => write!(f, "Could not load settings"),

            InitializeErrorReason::ManagementService => {
                write!(f, "Could not start management service")
            }

            InitializeErrorReason::ManualProvisioningClient => {
                write!(f, "Could not initialize manual provisioning client")
            }

            InitializeErrorReason::ModuleRuntime => {
                write!(f, "Could not initialize module runtime")
            }

            InitializeErrorReason::NotConfigured => write!(
                f,
                "Edge device information is required.\n\
                 Please update the config.yaml and provide the IoTHub connection information.\n\
                 See {} for more details.",
                if cfg!(windows) {
                    "https://aka.ms/iot-edge-configure-windows"
                } else {
                    "https://aka.ms/iot-edge-configure-linux"
                }
            ),

            InitializeErrorReason::PrepareWorkloadCa => {
                write!(f, "Could not prepare workload CA certificate")
            }

            #[cfg(windows)]
            InitializeErrorReason::RegisterWindowsService => {
                write!(f, "Could not register Windows Service control handle")
            }

            InitializeErrorReason::RemoveExistingModules => {
                write!(f, "Could not remove existing modules")
            }

            InitializeErrorReason::SaveSettings => write!(f, "Could not save settings file"),

            #[cfg(windows)]
            InitializeErrorReason::StartWindowsService => {
                write!(f, "Could not start as Windows Service")
            }

            InitializeErrorReason::Tokio => write!(f, "Could not initialize tokio runtime"),

            InitializeErrorReason::WorkloadService => write!(f, "Could not start workload service"),
        }
    }
}

// The use of the Mutex below is an artifact of trying to unify 2 different error
// handling crates. `windows_service` uses `error_chain` and we use `failure`.
// `error_chain`'s error type does not implement `Sync` unfortunately (they have
// an open PR to address that). But `failure` requires errors to implement `Sync`.
// So this `Mutex` helps us work around the problem.
#[cfg(windows)]
#[derive(Debug, Fail)]
pub struct ServiceError(Mutex<WindowsServiceError>);

#[cfg(windows)]
impl From<WindowsServiceError> for ServiceError {
    fn from(err: WindowsServiceError) -> Self {
        ServiceError(Mutex::new(err))
    }
}

#[cfg(windows)]
impl Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.lock().unwrap().fmt(f)
    }
}
