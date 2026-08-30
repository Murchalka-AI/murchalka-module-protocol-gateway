using Murchalka.ProtocolGateway.Runtime;

using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    shutdown.Cancel();
};

await using var connection = await ModuleConnection.ConnectAsync(shutdown.Token);
await connection.RunAsync(shutdown.Token);
