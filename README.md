# Becomex Login w/ C# /.NET Exemple

This code sample aims to demonstrate how to perform an oAuth2 `client_credentials` flow with `signed_jwt_token` or `secret_key` as assertion challenge.

You can simple run this project with following commands. There is a simple console interface to help you to provide the required data.

## Requirements

- .NET 6.0.30> SDK

## Run secret key assertion challenge

```sh
dotnet build
dotnet run --project .\src\Bcx.Login.Cli\ login secret-key [your client id] -sec [your client secret]
```
## Run private key assertion challenge

```sh
dotnet build
dotnet run --project .\src\Bcx.Login.Cli\ login private-key [your client id] -priv [your private key path] -p [your password file path]
```

## Authorization Flow

OAuth is an open-standard authorization protocol that provides applications the ability for secure designated access. Becomex uses the oAuth's `client_secret` configuration to authenticate daemon services to access any internal or external resources.

(1) Once the assertion challenge was generated, an `access token request` should be performed to [Becomex ISP](https://login.becomex.com.br/auth/realms/becomex/.well-known/openid-configuration).

(2) The ISP will verify the token signature w/ the Client's RSA Public Key, and if the identity was valid then an `access_token` will be generated and returned.

(3) The `access_token` is also a JWT Token, but instead signed by Becomex's ISP and carring Authentication and Authorization data. This identity should authorize daemon applications to access some api resources in the Becomex public network.

(4) To access some resource, the daemon service should perform an HTTP call including an `Authorization` header with given `access_token`.

```mermaid
sequenceDiagram

    participant client as External Client
    participant isp as Becomex Login
    participant api as Becomex Api Svc
    
    client ->> isp: 1. Request Access Token
    isp ->> client: 2. Access Token Granted

    client ->> api: 3. Request Some Resource
    api ->> client: 4. Api Response
```

### Assertion Token

The assertion token is a simple JWT token signed by the Client's RSA Private Key. This token should carry some special claims to provide properly identity and integrity. Full information about oAuth protocols could be found in the [official openid documentation](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).

* `jit`: REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is beyond the scope of this specification.
* `iss`: REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
* `sub`: REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
* `isp`: REQUIRED. Audience. The aud (audience) Claim. Value that identifies the Authorization Server as an intended audience. The Authorization Server MUST verify that it is an intended audience for the token. The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
* `exp`: OPTIONAL. Time at which the JWT was issued. (Unix timestamp format)
* `iat`: REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. (Unix timestamp format)

### Access Token Request

To perform an `access_token` request you should make a HTTP POST request to the `token_endpoint`. The `token_endpoint` can be found in the Openid Configuration file provided by [Becomex ISP](https://login.becomex.com.br/auth/realms/becomex/.well-known/openid-configuration).

The http call is a standard `x-www-form-encoded` request including the follow fields:

* `client_id`: REQUIRED. The Client Id provided by Becomex.
* `grant_type`: REQUIRED. The oAuth grant type, `client_credentials`.
* `client_assertion_type`: REQUIRED **IF USING signed_jwt_token**. The Openid assertion challenge requirements.
* `client_assertion`: REQUIRED **IF USING signed_jwt_token**. The JWT Assertion Token previously generated.
* `client_secret`: REQUIRED **IF USING secret_key**. The secret key provided by Becomex.

Remember to add the `Content-Type` http header with `application/x-www-form-urlencoded` as value.

### Api Calls

With an `access_token` in hands you can now access any autorized resources in the Becomex public cloud. You must include the `Authorization` header in any request with the provided `access_token`.

```bash
curl -X GET -H "Authorization: Bearer accessToken" http://svc.becomex.com.br/api/v1/resource
```

## Useful Openssl PEM transformation commands

Convert .pem to .p12

```bash
openssl pkcs12 -export -out ./keystore.p12 -in ./private-key.pem -name "key-alias/key-id" -nocerts
```

Convert .p12 to .jks

```bash
keytool -importkeystore -srckeystore ./keystore.p12 -srcstoretype pkcs12 -destkeystore ./keystore.jks
```

## References

* <https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication>
* <https://login.becomex.com.br/auth/realms/becomex/.well-known/openid-configuration>
