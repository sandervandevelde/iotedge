// Copyright (c) Microsoft. All rights reserved.
namespace Microsoft.Azure.Devices.Edge.Hub.CloudProxy.Authenticators
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Azure.Devices.Common.Data;
    using Microsoft.Azure.Devices.Common.Security;
    using Microsoft.Azure.Devices.Edge.Hub.Core;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Device;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Identity;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Identity.Service;
    using Microsoft.Azure.Devices.Edge.Util;
    using Microsoft.Extensions.Logging;

    public class DeviceScopeCertificateAuthenticator : IAuthenticator
    {
        readonly IDeviceScopeIdentitiesCache deviceScopeIdentitiesCache;
        readonly string iothubHostName;
        readonly string edgeHubHostName;
        readonly IAuthenticator underlyingAuthenticator;
        readonly IList<X509Certificate2> trustBundle;

        public DeviceScopeCertificateAuthenticator(
            IDeviceScopeIdentitiesCache deviceScopeIdentitiesCache,
            string iothubHostName,
            string edgeHubHostName,
            IAuthenticator underlyingAuthenticator,
            IList<X509Certificate2> trustBundle)
        {
            this.underlyingAuthenticator = Preconditions.CheckNotNull(underlyingAuthenticator, nameof(underlyingAuthenticator));
            this.deviceScopeIdentitiesCache = Preconditions.CheckNotNull(deviceScopeIdentitiesCache, nameof(deviceScopeIdentitiesCache));
            this.iothubHostName = Preconditions.CheckNonWhiteSpace(iothubHostName, nameof(iothubHostName));
            this.edgeHubHostName = Preconditions.CheckNotNull(edgeHubHostName, nameof(edgeHubHostName));
            this.trustBundle = Preconditions.CheckNotNull(trustBundle, nameof(trustBundle));
        }

        public Task<bool> AuthenticateAsync(IClientCredentials clientCredentials)
            => this.AuthenticateAsync(clientCredentials, false);

        public Task<bool> ReauthenticateAsync(IClientCredentials clientCredentials)
            => this.AuthenticateAsync(clientCredentials, true);

        async Task<bool> AuthenticateAsync(IClientCredentials clientCredentials, bool reAuthenticating)
        {
            if (!(clientCredentials is ICertificateCredentials certificateCredentials))
            {
                return false;
            }

            Option<ServiceIdentity> serviceIdentity = await this.deviceScopeIdentitiesCache.GetServiceIdentity(clientCredentials.Identity.Id, reAuthenticating);
            if (serviceIdentity.HasValue)
            {
                try
                {
                    bool isAuthenticated = await serviceIdentity.Map(s => this.AuthenticateInternalAsync(certificateCredentials, s)).GetOrElse(Task.FromResult(false));
                    Events.ReauthenticatedInScope(clientCredentials.Identity, isAuthenticated);
                    return isAuthenticated;
                }
                catch (Exception e)
                {
                    Events.ErrorAuthenticating(e, clientCredentials);
                    return await this.underlyingAuthenticator.ReauthenticateAsync(clientCredentials);
                }
            }
            else
            {
                Events.ServiceIdentityNotFound(clientCredentials.Identity);
                return await this.underlyingAuthenticator.ReauthenticateAsync(clientCredentials);
            }
        }

        async Task<bool> AuthenticateInternalAsync(ICertificateCredentials certificateCredentials, ServiceIdentity serviceIdentity) =>
            await Task.FromResult(ValidateCredentials(certificateCredentials, serviceIdentity));

        bool ValidateCredentials(ICertificateCredentials certificateCredentials, ServiceIdentity serviceIdentity) =>
            this.ValidateCertificateAndChain(certificateCredentials.ClientCertificate, certificateCredentials.ClientCertificateChain) &&
            this.ValidateCertificateWithSecurityIdentity(certificateCredentials, serviceIdentity);

        bool ValidateCertificateAndChain(X509Certificate2 certificate, IList<X509Certificate2> certChain) =>
            CertificateHelper.ValidateClientCert(certificate, certChain, Events.Log);

        bool ValidateCertificateWithSecurityIdentity(ICertificateCredentials certificateCredentials, ServiceIdentity serviceIdentity)
        {
            bool result;

            if (serviceIdentity.Status != ServiceIdentityStatus.Enabled)
            {
                Events.ServiceIdentityNotEnabled(serviceIdentity);
                result = false;
            }
            else if (serviceIdentity.Authentication.Type == ServiceAuthenticationType.CertificateThumbprint)
            {
                result = serviceIdentity.Authentication.X509Thumbprint.Map(
                t =>
                {
                    List<string> thumbprints = new List<string>() { t.PrimaryThumbprint, t.SecondaryThumbprint };
                    return CertificateHelper.ValidateCertificateThumbprint(certificateCredentials.ClientCertificate, thumbprints);
                }).GetOrElse(() => throw new InvalidOperationException($"Unable to validate certificate because the service identity has empty thumbprints"));
                if (!result) Events.ThumbprintMismatch(serviceIdentity.Id);
            }
            else if (serviceIdentity.Authentication.Type == ServiceAuthenticationType.CertificateAuthority)
            {
                if (certificateCredentials.Identity is IModuleIdentity)

                {
                    result = serviceIdentity.ModuleId.Map(
                    moduleId =>
                    {
                        return CertificateHelper.ValidateSanUri(certificateCredentials.ClientCertificate, iothubHostName,
                                                                serviceIdentity.DeviceId, moduleId);
                    }).GetOrElse(() => throw new InvalidOperationException($"Unable to validate certificate because the service identity is not a module"));
                    if (!result) Events.UnsupportedServiceIdentityType(serviceIdentity);
                }
                else
                {
                    result = CertificateHelper.ValidateCommonName(certificateCredentials.ClientCertificate, serviceIdentity.DeviceId);
                    if (!result) Events.UnsupportedServiceIdentityType(serviceIdentity);
                }

                if (result && (CertificateHelper.ValidateClientCertCAChain(certificateCredentials.ClientCertificate,
                                                                           certificateCredentials.ClientCertificateChain,
                                                                           this.trustBundle, Events.Log)))
                {
                    Events.UnsupportedServiceIdentityType(serviceIdentity);
                    result = false;
                }
            }
            else
            {
                Events.InvalidServiceIdentityType(serviceIdentity);
                result = false;
            }

            return result;
        }

        static class Events
        {
            public static readonly ILogger Log = Logger.Factory.CreateLogger<DeviceScopeCertificateAuthenticator>();
            const int IdStart = CloudProxyEventIds.CertificateCredentialsAuthenticator;

            enum EventIds
            {
                UnsupportedIdentityType = IdStart,
                ThumbprintMismatch,
                InvalidCommonName,
                InvalidHostName,
                InvalidAudience,
                IdMismatch,
                KeysMismatch,
                InvalidServiceIdentityType,
                ErrorAuthenticating,
                ServiceIdentityNotEnabled,
                TokenExpired,
                ErrorParsingToken,
                ServiceIdentityNotFound,
                AuthenticatedInScope,
                
            }

            public static void UnsupportedServiceIdentityType(ServiceIdentity serviceIdentity)
            {
                Log.LogWarning((int)EventIds.UnsupportedIdentityType, $"Error authenticating {serviceIdentity.Id} using X.509 certificates since this is identity type is unsupported.");
            }

            public static void ThumbprintMismatch(string id)
            {
                Log.LogWarning((int)EventIds.KeysMismatch, $"Error authenticating certificate for {id} because the certificate thumbprint did not match the primary or the secondary thumbprints.");
            }

            public static void InvalidCommonName(string id)
            {
                Log.LogWarning((int)EventIds.KeysMismatch, $"Error authenticating certificate for {id} because the certificate thumbprint did not match the primary or the secondary thumbprints.");
            }

            public static void InvalidCommonName(string id, string hostName, string iotHubHostName, string edgeHubHostName)
            {
                Log.LogWarning((int)EventIds.InvalidHostName, $"Error authenticating token for {id} because the audience hostname {hostName} does not match IoTHub hostname {iotHubHostName} or the EdgeHub hostname {edgeHubHostName}.");
            }

            public static void InvalidAudience(string audience, IIdentity identity)
            {
                Log.LogWarning((int)EventIds.InvalidAudience, $"Error authenticating token for {identity.Id} because the audience {audience} is invalid.");
            }

            public static void IdMismatch(string audience, IIdentity identity, string deviceId)
            {
                Log.LogWarning((int)EventIds.IdMismatch, $"Error authenticating token for {identity.Id} because the deviceId {deviceId} in the identity does not match the audience {audience}.");
            }

            public static void KeysMismatch(string id, Exception exception)
            {
                Log.LogWarning((int)EventIds.KeysMismatch, $"Error authenticating token for {id} because the token did not match the primary or the secondary key. Error - {exception.Message}");
            }

            public static void InvalidServiceIdentityType(ServiceIdentity serviceIdentity)
            {
                Log.LogWarning((int)EventIds.InvalidServiceIdentityType, $"Error authenticating token for {serviceIdentity.Id} because the service identity authentication type is unexpected - {serviceIdentity.Authentication.Type}");
            }

            public static void ErrorAuthenticating(Exception exception, IClientCredentials credentials)
            {
                Log.LogWarning((int)EventIds.ErrorAuthenticating, exception, $"Error authenticating credentials for {credentials.Identity.Id}");
            }

            public static void ServiceIdentityNotEnabled(ServiceIdentity serviceIdentity)
            {
                Log.LogWarning((int)EventIds.ServiceIdentityNotEnabled, $"Error authenticating token for {serviceIdentity.Id} because the service identity is not enabled");
            }

            public static void TokenExpired(IIdentity identity)
            {
                Log.LogWarning((int)EventIds.TokenExpired, $"Error authenticating token for {identity.Id} because the token has expired.");
            }

            public static void ErrorParsingToken(IIdentity identity, Exception exception)
            {
                Log.LogWarning((int)EventIds.ErrorParsingToken, exception, $"Error authenticating token for {identity.Id} because the token could not be parsed");
            }

            public static void ServiceIdentityNotFound(IIdentity identity)
            {
                Log.LogDebug((int)EventIds.ServiceIdentityNotFound, $"Service identity for {identity.Id} not found. Using underlying authenticator to authenticate");
            }

            public static void AuthenticatedInScope(IIdentity identity, bool isAuthenticated)
            {
                string authenticated = isAuthenticated ? "authenticated" : "not authenticated";
                Log.LogInformation((int)EventIds.AuthenticatedInScope, $"Client {identity.Id} in device scope {authenticated} locally.");
            }

            public static void ReauthenticatedInScope(IIdentity identity, bool isAuthenticated)
            {
                string authenticated = isAuthenticated ? "reauthenticated" : "not reauthenticated";
                Log.LogDebug((int)EventIds.AuthenticatedInScope, $"Client {identity.Id} in device scope {authenticated} locally.");
            }
        }
    }
}
