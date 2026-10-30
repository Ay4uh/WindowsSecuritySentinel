using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WindowsSecuritySentinel.Core;

public static class SignatureVerifier
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid(NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2);
    private static readonly Guid DRIVER_ACTION_VERIFY = new Guid("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}");

    public static (bool IsValid, string SignerName, string Details) VerifyFileSignature(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return (false, "File Not Found", "The target file does not exist on disk.");

        // 1. First, check Embedded Authenticode Signature
        var embeddedResult = VerifyEmbeddedSignature(filePath);
        if (embeddedResult.IsValid)
            return embeddedResult;

        // 2. If embedded check fails or file has no embedded signature, check Windows Catalog (.cat)
        var catalogResult = VerifyCatalogSignature(filePath);
        if (catalogResult.IsValid)
            return catalogResult;

        return embeddedResult.SignerName != "Unsigned" ? embeddedResult : catalogResult;
    }

    private static (bool IsValid, string SignerName, string Details) VerifyEmbeddedSignature(string filePath)
    {
        try
        {
            var fileInfo = new NativeMethods.WINTRUST_FILE_INFO(filePath);
            var trustData = new NativeMethods.WINTRUST_DATA(fileInfo);

            int result = NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
            trustData.Dispose();

            if (result == 0) // TRUST_E_PROVIDER_UNKNOWN = 0 -> S_OK (0)
            {
                string signer = ExtractSignerName(filePath);
                return (true, signer, "Valid Authenticode embedded signature verified by WinVerifyTrust.");
            }

            // Distinguish reasons
            return result switch
            {
                unchecked((int)0x800B0100) => (false, "Unsigned", "No signature found in file."), // TRUST_E_NOSIGNATURE
                unchecked((int)0x80096010) => (false, "Tampered / Corrupt", "The digital signature hash does not match file contents."), // TRUST_E_BAD_DIGEST
                unchecked((int)0x800B0101) => (false, "Expired Certificate", "A required certificate is not within its validity period."), // CERT_E_EXPIRED
                unchecked((int)0x800B0109) => (false, "Untrusted Root", "A certificate chain processed, but terminated in a root certificate which is not trusted."), // CERT_E_UNTRUSTEDROOT
                unchecked((int)0x800B010E) => (false, "Revoked Certificate", "The certificate was revoked by the issuer."), // CERT_E_REVOKED
                _ => (false, "Invalid Signature", $"WinVerifyTrust failed with HRESULT 0x{result:X8}.")
            };
        }
        catch (Exception ex)
        {
            return (false, "Error", $"Signature check encountered error: {ex.Message}");
        }
    }

    private static (bool IsValid, string SignerName, string Details) VerifyCatalogSignature(string filePath)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hFile = IntPtr.Zero;
        try
        {
            if (!NativeMethods.CryptCATAdminAcquireContext(out hCatAdmin, DRIVER_ACTION_VERIFY, 0))
                return (false, "Unsigned", "Failed to acquire catalog admin context.");

            hFile = NativeMethods.CreateFile(
                filePath,
                NativeMethods.GENERIC_READ,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero,
                NativeMethods.OPEN_EXISTING,
                NativeMethods.FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);

            if (hFile == NativeMethods.INVALID_HANDLE_VALUE || hFile == IntPtr.Zero)
                return (false, "Unsigned", "Cannot open file handle to compute catalog hash.");

            int hashSize = 0;
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, null, 0) || hashSize <= 0)
                return (false, "Unsigned", "Failed to compute catalog hash size.");

            byte[] hash = new byte[hashSize];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, hash, 0))
                return (false, "Unsigned", "Failed to compute catalog hash.");

            NativeMethods.CloseHandle(hFile);
            hFile = IntPtr.Zero;

            IntPtr hCatInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero)
                return (false, "Unsigned", "File has neither an embedded signature nor a Windows OS Catalog match.");

            var catInfo = new NativeMethods.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(NativeMethods.CATALOG_INFO)) };
            if (NativeMethods.CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
            {
                string catPath = catInfo.wszCatalogFile;
                string hashStr = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();

                var catalogInfoStruct = new NativeMethods.WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(NativeMethods.WINTRUST_CATALOG_INFO)),
                    pcwszCatalogFilePath = catPath,
                    pcwszMemberTag = hashStr,
                    pcwszMemberFilePath = filePath,
                    hMemberFile = IntPtr.Zero,
                    pbCalculatedMessageDigest = IntPtr.Zero,
                    cbCalculatedMessageDigest = 0,
                    pcCatalogContext = IntPtr.Zero
                };

                var trustData = new NativeMethods.WINTRUST_DATA(catalogInfoStruct);
                int result = NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
                trustData.Dispose();
                NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

                if (result == 0)
                {
                    return (true, "Microsoft Windows Catalog Verified", $"Signed via Windows Catalog: {Path.GetFileName(catPath)}");
                }
            }
            else
            {
                NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }

            return (false, "Unsigned", "No valid Windows Catalog signature found.");
        }
        catch (Exception ex)
        {
            return (false, "Error", $"Catalog verification error: {ex.Message}");
        }
        finally
        {
            if (hFile != IntPtr.Zero && hFile != NativeMethods.INVALID_HANDLE_VALUE)
                NativeMethods.CloseHandle(hFile);

            if (hCatAdmin != IntPtr.Zero)
                NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static string ExtractSignerName(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            var cert2 = new X509Certificate2(cert);
            return cert2.GetNameInfo(X509NameType.SimpleName, false) ?? cert2.Subject;
        }
        catch
        {
            return "Valid Authenticode (Signer details unavailable)";
        }
    }
}
