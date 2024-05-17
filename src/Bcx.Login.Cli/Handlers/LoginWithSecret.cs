using Newtonsoft.Json.Linq;

namespace Bcx.Login.Cli.Handlers
{
    public static class LoginWithSecret
    {
        public async static Task HandleAsync(
            string clientIdArg,
            string? secretKeyOpt = null
        )
        {
            Console.WriteLine("Generating bearer token with client_id + secret key");

            if (string.IsNullOrWhiteSpace(secretKeyOpt))
                throw new IOException("Unable to resolve secretKeyOpt");

            var clientToken = new HttpClient();

            var requestToken = new HttpRequestMessage
            {
                RequestUri = new Uri("https://login.becomex.com.br/auth/realms/becomex/protocol/openid-connect/token"),
                Method = HttpMethod.Post,
                Content = new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new("client_id", clientIdArg),
                    new("grant_type", "client_credentials"),
                    new("scope", "openid"),
                    new("client_secret", secretKeyOpt)
                })
            };

            var responseToken = await clientToken.SendAsync(requestToken);

            if (responseToken.IsSuccessStatusCode)
                Console.WriteLine($"Bearer: {JObject.Parse(await responseToken.Content.ReadAsStringAsync())["access_token"]}");
            else
                Console.WriteLine("Fail");
        }
    }
}