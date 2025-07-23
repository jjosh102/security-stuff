var builder = DistributedApplication.CreateBuilder(args);
var keycloak = builder.AddKeycloak("keycloak", 8080)
                      .WithDataVolume()
                      .WithExternalHttpEndpoints();
builder.Build().Run();
