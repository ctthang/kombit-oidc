﻿using System;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore
{
    public static class ConfigurationExtensions
    {
        public static string Scope(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:Scope"];
        }

        public static string ClientId(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClientId"];
        }

        public static string ClientSecret(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClientSecret"];
        }

        public static string ResponseType(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ResponseType"];
        }

        public static string ResponseMode(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ResponseMode"];
        }

        public static string ClaimsIssuer(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClaimsIssuer"].TrimEnd('/');
        }

        public static string IssuerDomain(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IssuerDomain"].TrimEnd('/');
        }

        public static string AuthorizationEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/oauth2/authorize.idp";
        }

        public static string TokenEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/oauth2/token.idp";
        }

        public static string UserInfoEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/openidconnect/userinfo.idp";
        }

        public static string EndSessionEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/openidconnect/logout.idp";
        }

        public static bool SessionManagementEnabled(this IConfiguration configuration)
        {
            return configuration.CheckSessionIframeUri() != null;
        }

        public static Uri CheckSessionIframeUri(this IConfiguration configuration)
        {
            var sessionUri = configuration["OpenIdConnectOptions:CheckSessionIframeUri"];
            if (string.IsNullOrEmpty(sessionUri))
            {
                return null;
            }
            return new Uri(sessionUri);
        }

        public static bool UsePKCE(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:UsePKCE"] == "true";
        }

        public static bool RequireNonce(this IConfiguration configuration)
        {
            return bool.Parse(configuration["OpenIdConnectOptions:RequireNonce"]);
        }

        public static bool EnableSessionManagement(this IConfiguration configuration)
        {
            var enableSessionManagement = configuration["OpenIdConnectOptions:EnableSessionManagement"];
            bool.TryParse(enableSessionManagement, out bool result);
            return result;
        }

        public static bool EnablePostLogout(this IConfiguration configuration)
        {
            var enablePostLogout = configuration["OpenIdConnectOptions:EnablePostLogout"];
            bool.TryParse(enablePostLogout, out bool result);
            return result;
        }

        public static OpenIdConnectRedirectBehavior AuthorizationEndpointMethod(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:AuthorizationEndpointMethod"] == "POST"? OpenIdConnectRedirectBehavior.FormPost : OpenIdConnectRedirectBehavior.RedirectGet;
        }

        public static string TokenAuthnMethod(this IConfiguration configuration)
        {
            var method = configuration["OpenIdConnectOptions:TokenAuthnMethod"];
            if (string.IsNullOrEmpty(method))
            {
                return "client_secret_post";
            }

            return method;
        }

        public static string IdTokenDecryptionCertPath(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IdTokenDecryptionCertPath"];
        }

        public static string IdTokenDecryptionCertPassword(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IdTokenDecryptionCertPassword"];
        }
    }
}
