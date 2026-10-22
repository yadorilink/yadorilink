using System;
using System.Threading.Tasks;
using YadoriLink.Native;
using YadoriLink.Native.Core;

// Loading the library checks its API checksums against the generated binding;
// a mismatch throws on the first call. With no daemon running the status
// watch reports it as unavailable, which is still an answer.
var core = new ClientCore(new CoreConfig(new DaemonLaunch.SpawnBinary(null)));
var account = await core.AccountStatus();
Console.WriteLine($"account status: {account.SignIn.GetType().Name}");

using var watch = core.WatchStatus(TimeSpan.FromSeconds(1));
var next = watch.Next();
if (await Task.WhenAny(next, Task.Delay(TimeSpan.FromSeconds(30))) != next)
{
    Console.Error.WriteLine("the status watch delivered nothing within 30 seconds");
    return 1;
}
var update = await next;
Console.WriteLine($"status update: {update?.GetType().Name ?? "none"}");
watch.Cancel();
return update is null ? 1 : 0;
