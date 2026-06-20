using NuGet.Versioning;

namespace NuGetCheck.Models;

/// <summary>A package id paired with its installed NuGet version.</summary>
public sealed record PackageRef(string Id, NuGetVersion Version);
