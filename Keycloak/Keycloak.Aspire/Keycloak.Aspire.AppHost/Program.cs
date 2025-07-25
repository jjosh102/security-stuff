var builder = DistributedApplication.CreateBuilder(args);
var keycloak = builder.AddKeycloak("keycloak", 8080)
                      .WithDataVolume()
                      .WithExternalHttpEndpoints()
                      .WithLifetime(ContainerLifetime.Persistent);

var api = builder.AddProject<Projects.Keycloak_Api>("api")
                 .WithExternalHttpEndpoints()
                 .WithReference(keycloak);

builder.Build().Run();
