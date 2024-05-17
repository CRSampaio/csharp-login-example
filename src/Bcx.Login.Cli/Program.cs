using System.CommandLine;
using Bcx.Login.Cli.Handlers;

// Global Options -------------
var clientIdArg = new Argument<string>(
    "client",
    "The name of the client registered on login.becomex.com.br. "
    + "This value will define the prefix of every automatic generated or loaded file.");

var privateKeyFileOpt = new Option<string?>(
    new string[] { "-priv", "--private-key-file" },
    "A path to an existing private key.");

var secretKeyOpt = new Option<string?>(
    new string[] { "-sec", "--secret-key-value" },
    "The secrey key associated with the client ID.");

var passwordPathOpt = new Option<string?>(
    new string[] { "-p", "--password" },
    "A path to file w/ password stored; used to encrypt/decrypt the private key.");

var genTokenPrivateKeyCmd = new Command("private-key",
                                        "Generate a bearer token in Becomex Login API using client ID and private key");
genTokenPrivateKeyCmd.SetHandler(LoginWithAssertion.HandleAsync, clientIdArg, privateKeyFileOpt, passwordPathOpt);
genTokenPrivateKeyCmd.AddArgument(clientIdArg);
genTokenPrivateKeyCmd.AddOption(privateKeyFileOpt);
genTokenPrivateKeyCmd.AddOption(passwordPathOpt);

var genTokenSecretCmd = new Command("secret-key",
                                    "Generate a bearer token in Becomex Login API using client ID and secret key");
genTokenSecretCmd.SetHandler(LoginWithSecret.HandleAsync, clientIdArg, secretKeyOpt);
genTokenSecretCmd.AddArgument(clientIdArg);
genTokenSecretCmd.AddOption(secretKeyOpt);

var loginCmd = new Command("login", "Becomex Login API tools");
loginCmd.AddCommand(genTokenPrivateKeyCmd);
loginCmd.AddCommand(genTokenSecretCmd);

var app = new RootCommand("Becomex Authentication CLI");
app.AddCommand(loginCmd);

await app.InvokeAsync(args);
