using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests.Infrastructure;

/// <summary>API mínima em TestServer (sem rede) para os testes de ponta a ponta.</summary>
internal sealed class TestApp : IAsyncDisposable
{
    private TestApp(WebApplication app, TestLoggerProvider logs)
    {
        App = app;
        Logs = logs;
        Client = app.GetTestClient();
        Client.BaseAddress = new Uri("https://localhost/");
    }

    public WebApplication App { get; }

    public HttpClient Client { get; }

    public TestLoggerProvider Logs { get; }

    public IServiceProvider Services => App.Services;

    public static async Task<TestApp> StartAsync(
        Action<WebApplicationBuilder> configureServices,
        Action<WebApplication> map,
        IDictionary<string, string?>? configuration = null,
        string environment = "Testing")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(configuration ?? new Dictionary<string, string?>());

        var logs = new TestLoggerProvider();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        builder.Logging.SetMinimumLevel(LogLevel.Debug);

        configureServices(builder);

        var app = builder.Build();
        map(app);
        await app.StartAsync();
        return new TestApp(app, logs);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
    }
}
