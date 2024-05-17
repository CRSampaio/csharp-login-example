using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Bcx.Login.Cli.Consts;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Bcx.Login.Cli.Handlers
{
    public static class LoginWithAssertion
    {
        public async static Task HandleAsync(
            string clientIdArg,
            string? privateKeyFileOpt = null,
            string? passwordPathOpt = null
        )
        {
            Console.WriteLine("Generating bearer token with client_id + private key");

            if (string.IsNullOrWhiteSpace(privateKeyFileOpt))
                throw new IOException("Unable to resolve privateKeyFileOpt");
            if (string.IsNullOrWhiteSpace(passwordPathOpt))
                throw new IOException("Unable to resolve passwordOpt");

            var rsa = RSA.Create();
            var file = File.ReadAllText(privateKeyFileOpt);
            var password = File.ReadAllText(passwordPathOpt);
            rsa.ImportFromEncryptedPem(file, password);

            var rsaSecurityKey = new RsaSecurityKey(rsa);
            var signingCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                        new JwtHeader(signingCredentials),
                        new JwtPayload(
                            clientIdArg,
                            BecomexConsts.BaseUrl,
                            new[] {
                            new Claim("sub", clientIdArg),
                            new Claim("jti", Guid.NewGuid().ToString())
                            },
                            DateTime.UtcNow.AddMinutes(-5),
                            DateTime.UtcNow.AddHours(3)));

            var clientAssertion = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            var clientToken = new HttpClient();

            var requestToken = new HttpRequestMessage
            {
                RequestUri = new Uri(BecomexConsts.TokenUrl),
                Method = HttpMethod.Post,
                Content = new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new("client_id", clientIdArg),
                    new("grant_type", "client_credentials"),
                    new("scope", "openid"),
                    new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new("client_assertion", clientAssertion)
                })
            };

            var responseToken = await clientToken.SendAsync(requestToken);

            if (responseToken.IsSuccessStatusCode)
                Console.WriteLine($"Bearer {JObject.Parse(await responseToken.Content.ReadAsStringAsync())["access_token"]}");
            else
                Console.WriteLine("Fail");
        }
    }
}