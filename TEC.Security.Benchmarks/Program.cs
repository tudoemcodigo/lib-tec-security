using BenchmarkDotNet.Running;

// Exemplos (sempre em Release):
//   dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter *
//   dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter *ApiKey* --runtimes net8.0 net10.0
//   dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter * --job short   (execução rápida, menos precisa)
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
