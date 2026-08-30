using Murchalka.ModuleProtocol.Json;
using Murchalka.ModuleSdk.Testing;

namespace Murchalka.ProtocolGateway.Tests;

/// <summary>Verifies repository and capability conformance.</summary>
public sealed class RepositoryConformanceTests
{
    /// <summary>Verifies schemas, contracts, permissions, and lifecycle declarations.</summary>
    [Fact]
    public void RepositoryConforms()
    {
        var root = RepositoryRootLocator.Find();
        var schemas = Path.Combine(Directory.GetParent(root)!.FullName, "murchalka-module-protocol", "schemas");
        var conformance = Directory.Exists(schemas)
            ? new ModuleRepositoryConformance(new CanonicalSchemaValidator(schemas))
            : new ModuleRepositoryConformance();
        var report = conformance.Validate(root);
        Assert.True(report.Passed, string.Join(Environment.NewLine, report.Findings.Select(value => value.Message)));
    }
}
