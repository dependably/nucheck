using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Dependably.NuCheck.Facts.Nuget;

namespace Dependably.NuCheck.Facts.Il;

/// <param name="Kind"><c>il-type-ref</c> or <c>il-member-ref</c>.</param>
/// <param name="Symbol">Fully-qualified external type or member name, e.g. <c>Newtonsoft.Json.JsonConvert.DeserializeObject</c>.</param>
/// <param name="AssemblyName">Simple name of the assembly that defines the referenced type.</param>
public readonly record struct ReferenceInfo(string Kind, string Symbol, string AssemblyName);

/// <summary>
/// Enumerates the MemberReference/TypeReference tables of first-party
/// *compiled* output with System.Reflection.Metadata (no assembly loading — the
/// same no-load-time-execution approach <see cref="NamespaceMap"/> uses for
/// package DLLs). Each reference names the assembly it resolves to; mapping that
/// assembly back to a package (via the closure's assembly names) is the
/// consumer's join.
///
/// This is member/type-*reference* evidence, not a call graph or proof of
/// execution: it reports what the compiler kept, and only that.
/// </summary>
public static class IlReferenceReader
{
    /// The project's own build output: `bin/**/<AssemblyName>.dll`, matching
    /// the .csproj file's name (the SDK's default AssemblyName). Multiple
    /// matches (e.g. both Debug and Release present) resolve deterministically
    /// to the lexicographically-first path.
    public static string? FindOutputAssembly(string csprojPath, string srcDir, List<UnanalyzableEntry> unanalyzable)
    {
        var projectDir = Path.GetDirectoryName(csprojPath)!;
        var binDir = Path.Combine(projectDir, "bin");
        if (!Directory.Exists(binDir)) return null;
        var assemblyName = Path.GetFileNameWithoutExtension(csprojPath);
        string[] candidates;
        try
        {
            candidates = Directory.GetFiles(binDir, $"{assemblyName}.dll", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, binDir), UnanalyzableEntry.KindDirectory, $"unlistable directory: {ex.Message}"));
            return null;
        }
        if (candidates.Length == 0) return null;
        Array.Sort(candidates, StringComparer.Ordinal);
        return candidates[0];
    }

    // ECMA-335 §II.23.2.12 Type: the leading element-type byte for a
    // constructed generic type ("GENERICINST"), and the CLASS/VALUETYPE tag
    // byte that follows it. These aren't exposed as SignatureTypeCode members
    // (CLASS/VALUETYPE are qualifiers inside the blob, not standalone type
    // codes), so they're named locally.
    private const byte SigGenericInst = 0x15;
    private const byte SigElementTypeClass = 0x12;
    private const byte SigElementTypeValueType = 0x11;

    /// <summary>
    /// A MemberReference whose <c>Parent</c> is a
    /// <see cref="TypeSpecificationHandle"/> — a member invoked on a *closed
    /// generic type* (<c>List&lt;T&gt;.Add</c>, <c>Cache&lt;T&gt;.Get</c>) —
    /// would otherwise be invisible. This decodes just enough of the TypeSpec's
    /// signature blob (ECMA-335 §II.23.2.12: <c>GENERICINST (CLASS|VALUETYPE)
    /// TypeDefOrRefOrSpecEncoded GenArgCount Type*</c>) to recover the
    /// underlying generic type's <see cref="TypeReferenceHandle"/> — only that
    /// leading token is needed, never the type arguments, so a full
    /// <c>SignatureDecoder</c> isn't needed.
    ///
    /// Anything that isn't a GENERICINST-over-a-TypeRef at the top level
    /// (arrays, pointers, a type argument substituted with a generic
    /// parameter, or a generic type whose own definition is a nested
    /// TypeSpec) returns <c>null</c> and the reference is skipped: an
    /// unrecognized shape is never guessed at, it is simply not reported.
    /// </summary>
    private static TypeReferenceHandle? TryResolveGenericInstantiationTypeRef(
        MetadataReader reader, TypeSpecificationHandle specHandle)
    {
        try
        {
            var spec = reader.GetTypeSpecification(specHandle);
            var blob = reader.GetBlobReader(spec.Signature);
            if (blob.RemainingBytes < 1 || blob.ReadByte() != SigGenericInst) return null;
            if (blob.RemainingBytes < 1) return null;
            var classOrValueType = blob.ReadByte();
            if (classOrValueType != SigElementTypeClass && classOrValueType != SigElementTypeValueType) return null;

            // TypeDefOrRefOrSpecEncoded (§II.23.2.8): a compressed unsigned
            // int whose low 2 bits select the table (0=TypeDef, 1=TypeRef,
            // 2=TypeSpec) and whose remaining bits are the 1-based row id.
            var coded = blob.ReadCompressedInteger();
            var table = coded & 0x3;
            var rid = coded >> 2;
            if (table != 1 || rid <= 0) return null; // TypeDef: first-party, not a package ref. Nested TypeSpec: not resolved here (fail-safe: skip, don't guess).
            return MetadataTokens.TypeReferenceHandle(rid);
        }
        catch
        {
            // Malformed/unexpected blob shape: skip rather than throw the
            // whole assembly scan — same fail-safe posture as elsewhere.
            return null;
        }
    }

    /// <summary>
    /// Walks TypeReferences (→ <c>il-type-ref</c>) and MemberReferences whose
    /// parent is a TypeReference or a TypeSpecification wrapping one (→
    /// <c>il-member-ref</c>; see <see cref="TryResolveGenericInstantiationTypeRef"/>
    /// for the latter). Method-body attribution (which first-party member
    /// makes each reference) is not recorded. Returns false — with the failure
    /// in <paramref name="unanalyzable"/> (kind <c>assembly</c>) — when the
    /// assembly's metadata could not be read at all.
    /// </summary>
    public static bool TryEnumerateReferences(
        string dllPath,
        string srcDir,
        List<UnanalyzableEntry> unanalyzable,
        out List<ReferenceInfo> references)
    {
        references = [];
        try
        {
            using var stream = File.OpenRead(dllPath);
            using var pe = new PEReader(stream);
            if (!pe.HasMetadata) return true;
            var reader = pe.GetMetadataReader();

            var typeRefInfo = new Dictionary<TypeReferenceHandle, (string Namespace, string Name, string Assembly)>();
            foreach (var trh in reader.TypeReferences)
            {
                var tr = reader.GetTypeReference(trh);
                if (tr.ResolutionScope.Kind != HandleKind.AssemblyReference) continue; // nested/module scope: not recorded.
                var asmRef = reader.GetAssemblyReference((AssemblyReferenceHandle)tr.ResolutionScope);
                var asmName = reader.GetString(asmRef.Name);
                var ns = reader.GetString(tr.Namespace);
                var name = reader.GetString(tr.Name);
                typeRefInfo[trh] = (ns, name, asmName);

                var typeFq = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                references.Add(new ReferenceInfo("il-type-ref", typeFq, asmName));
            }

            foreach (var mrh in reader.MemberReferences)
            {
                var mr = reader.GetMemberReference(mrh);
                (string Namespace, string Name, string Assembly)? info = null;
                if (mr.Parent.Kind == HandleKind.TypeReference)
                {
                    if (typeRefInfo.TryGetValue((TypeReferenceHandle)mr.Parent, out var direct)) info = direct;
                }
                else if (mr.Parent.Kind == HandleKind.TypeSpecification)
                {
                    // Member invoked on a closed generic type (List<T>.Add,
                    // Cache<T>.Get, ...). The underlying TypeRef is already in
                    // typeRefInfo — reader.TypeReferences enumerates the WHOLE
                    // TypeRef table, including rows only pointed at from a
                    // TypeSpec's encoded token, not just ones used as a
                    // MemberReference.Parent directly.
                    var underlying = TryResolveGenericInstantiationTypeRef(reader, (TypeSpecificationHandle)mr.Parent);
                    if (underlying is { } trh2 && typeRefInfo.TryGetValue(trh2, out var viaGeneric)) info = viaGeneric;
                }
                if (info is not { } resolved) continue;

                var memberName = reader.GetString(mr.Name);
                var typeFq = string.IsNullOrEmpty(resolved.Namespace) ? resolved.Name : $"{resolved.Namespace}.{resolved.Name}";
                references.Add(new ReferenceInfo("il-member-ref", $"{typeFq}.{memberName}", resolved.Assembly));
            }
            return true;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, dllPath), UnanalyzableEntry.KindAssembly, $"could not read IL metadata: {ex.Message}"));
            references = [];
            return false;
        }
    }
}
