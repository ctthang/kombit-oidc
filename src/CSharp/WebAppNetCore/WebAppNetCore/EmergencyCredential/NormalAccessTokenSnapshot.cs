using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class NormalAccessTokenSnapshot
    {
        public List<SnapshotClaim> Claims { get; private set; }
        public long Expires { get; private set; }

        // Only called with the access token returned by the server-side code exchange,
        // and the ID token already validated by the OIDC handler. Audience is not used
        // as an API authorization grant: this snapshot is bound to the configured client.
        public static NormalAccessTokenSnapshot Validate(string compact, JwtSecurityToken identityToken,
            string expectedIssuer, string expectedClient, IEnumerable<SecurityKey> signingKeys)
        {
            if (string.IsNullOrEmpty(compact) || compact.Length > 65536 || identityToken == null
                || identityToken.Issuer != expectedIssuer || string.IsNullOrEmpty(identityToken.Subject)
                || string.IsNullOrEmpty(expectedClient))
            {
                throw Rejected();
            }
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 65536 };
            handler.ValidateToken(compact, new TokenValidationParameters
            {
                ValidIssuer = expectedIssuer,
                ValidateIssuer = true,
                ValidateAudience = false,
                RequireAudience = false,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidAlgorithms = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" },
                ValidTypes = new[] { "at+jwt", "JWT" }
            }, out SecurityToken validated);
            if (!(validated is JwtSecurityToken token) || token.InnerToken != null)
            {
                throw Rejected();
            }
            var subjects = token.Claims.Where(claim => claim.Type == "sub").ToArray();
            var clients = token.Claims.Where(claim => claim.Type == "client_id").ToArray();
            var presenters = token.Claims.Where(claim => claim.Type == "azp").ToArray();
            if (subjects.Length != 1 || subjects[0].Value != identityToken.Subject
                || clients.Length != 1 || clients[0].Value != expectedClient
                || presenters.Length > 1 || (presenters.Length == 1 && presenters[0].Value != expectedClient))
            {
                throw Rejected();
            }
            var hashes = identityToken.Claims.Where(claim => claim.Type == "at_hash").ToArray();
            if (hashes.Length > 1)
            {
                throw Rejected();
            }
            if (hashes.Length == 1)
            {
                byte[] input = Encoding.ASCII.GetBytes(compact);
                byte[] digest;
                switch (identityToken.Header.Alg)
                {
                    case "RS256":
                    case "PS256":
                    case "ES256":
                        digest = SHA256.HashData(input);
                        break;
                    case "RS384":
                    case "PS384":
                    case "ES384":
                        digest = SHA384.HashData(input);
                        break;
                    case "RS512":
                    case "PS512":
                    case "ES512":
                        digest = SHA512.HashData(input);
                        break;
                    default:
                        throw Rejected();
                }
                byte[] expected = Encoding.ASCII.GetBytes(Base64UrlEncoder.Encode(digest.Take(digest.Length / 2).ToArray()));
                if (!CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(hashes[0].Value)))
                {
                    throw Rejected();
                }
            }
            return new NormalAccessTokenSnapshot
            {
                Claims = Copy(token.Claims.Select(claim => new SnapshotClaim { Type = claim.Type, Value = claim.Value, ValueType = claim.ValueType }).ToArray()),
                Expires = new DateTimeOffset(token.ValidTo, TimeSpan.Zero).ToUnixTimeSeconds()
            };
        }
        internal static List<SnapshotClaim> Copy(IReadOnlyList<SnapshotClaim> claims)
        {
            if (claims == null || claims.Count > 200 || claims.Any(claim => claim == null
                || string.IsNullOrWhiteSpace(claim.Type) || claim.Type.Length > 2048
                || claim.Value == null || claim.Value.Length > 16384
                || string.IsNullOrWhiteSpace(claim.ValueType) || claim.ValueType.Length > 256))
            {
                throw Rejected();
            }
            var result = claims.Where(claim => !EmergencyService.Reserved(claim.Type))
                .Select(claim => new SnapshotClaim { Type = claim.Type, Value = claim.Value, ValueType = claim.ValueType }).ToList();
            if (JsonSerializer.SerializeToUtf8Bytes(result).Length > 49152)
            {
                throw Rejected();
            }
            return result;
        }
        private static EmergencyFault Rejected() => new EmergencyFault(403, "normal_access_token_not_eligible");
    }
}
