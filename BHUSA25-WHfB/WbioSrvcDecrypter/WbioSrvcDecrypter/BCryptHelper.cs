using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

#region Struct Definitions

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct BCRYPT_KEY_DATA_BLOB_HEADER
{
    public uint dwMagic;      // Should be 0x4d42444b ('KDBM')
    public uint dwVersion;    // Usually 1
    public uint cbKeyData;
}

#endregion

#region SafeHandles

public sealed class SafeBCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeBCryptAlgorithmHandle() : base(true) { }

    protected override bool ReleaseHandle()
    {
        return BCryptDestroyAlgorithmProvider(handle) == 0;
    }

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyAlgorithmProvider(IntPtr hAlgorithm);
}

public sealed class SafeBCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeBCryptKeyHandle() : base(true) { }

    protected override bool ReleaseHandle()
    {
        return BCryptDestroyKey(handle) == 0;
    }

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);
}

#endregion

public static class AesCbcNative
{
    #region Constants

    private const string BCRYPT_AES_ALGORITHM = "AES";
    private const string BCRYPT_CHAIN_MODE = "ChainingMode";
    private const string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
    private const string BCRYPT_OBJECT_LENGTH = "ObjectLength";
    private const string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
    private const int BCRYPT_BLOCK_PADDING = 0x00000001;

    #endregion

    #region P/Invoke

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(
        out SafeBCryptAlgorithmHandle phAlgorithm,
        string pszAlgId,
        string pszImplementation,
        uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(
        SafeHandle hObject,
        string pszProperty,
        byte[] pbInput,
        int cbInput,
        uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptGetProperty(
        SafeHandle hObject,
        string pszProperty,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptImportKey(
        SafeBCryptAlgorithmHandle hAlgorithm,
        IntPtr hImportKey,
        string pszBlobType,
        out SafeBCryptKeyHandle phKey,
        byte[] pbKeyObject,
        int cbKeyObject,
        byte[] pbInput,
        int cbInput,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptEncrypt(
        SafeBCryptKeyHandle hKey,
        byte[] pbInput,
        int cbInput,
        IntPtr pPaddingInfo,
        byte[] pbIV,
        int cbIV,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        int dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(
        SafeBCryptKeyHandle hKey,
        byte[] pbInput,
        int cbInput,
        IntPtr pPaddingInfo,
        byte[] pbIV,
        int cbIV,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        int dwFlags);

    #endregion

    #region Public Methods

    // key data blob
    //public static SafeBCryptKeyHandle ImportAesKey(LockBoxProtectedData data, out SafeBCryptAlgorithmHandle hAlgorithm)
 public static SafeBCryptKeyHandle ImportAesKey(byte[] keyDataBlob, BCRYPT_KEY_DATA_BLOB_HEADER headerKeyDataBlob, out SafeBCryptAlgorithmHandle hAlgorithm)
    {
        int status = BCryptOpenAlgorithmProvider(out hAlgorithm, BCRYPT_AES_ALGORITHM, null, 0);
        if (status != 0)
            throw new Exception($"BCryptOpenAlgorithmProvider failed: 0x{status:X}");

        byte[] chainingMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_CBC + "\0");
        status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAIN_MODE, chainingMode, chainingMode.Length, 0);
        if (status != 0)
            throw new Exception($"BCryptSetProperty failed: 0x{status:X}");

        byte[] objLengthBuf = new byte[4];
        status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, objLengthBuf, objLengthBuf.Length, out int cbResult, 0);
        if (status != 0)
            throw new Exception($"BCryptGetProperty(ObjectLength) failed: 0x{status:X}");

        int keyObjectLength = BitConverter.ToInt32(objLengthBuf, 0);
        byte[] keyObject = new byte[keyObjectLength];

        // Create full blob: header + keyData
        int headerSize = Marshal.SizeOf<BCRYPT_KEY_DATA_BLOB_HEADER>();
        byte[] blob = new byte[headerSize + keyDataBlob.Length];

        GCHandle pinned = GCHandle.Alloc(blob, GCHandleType.Pinned);
        try
        {
            IntPtr ptr = pinned.AddrOfPinnedObject();
            Marshal.StructureToPtr(headerKeyDataBlob, ptr, false);
            Marshal.Copy(keyDataBlob, 0, ptr + headerSize, keyDataBlob.Length);
        }
        finally
        {
            pinned.Free();
        }

        status = BCryptImportKey(hAlgorithm, IntPtr.Zero, BCRYPT_KEY_DATA_BLOB, out SafeBCryptKeyHandle hKey, keyObject, keyObject.Length, blob, 0x40, 0);
        if (status != 0)
            throw new Exception($"BCryptImportKey failed: 0x{status:X}");

        return hKey;
    }

    //public static byte[] EncryptTemplate(LockBoxProtectedData data, byte[] plaintextTemplate)
    public static byte[] EncryptTemplate(byte[] IV, byte[] keyDataBlob, BCRYPT_KEY_DATA_BLOB_HEADER headerKeyDataBlob, byte[] plaintextTemplate)
    {
        SafeBCryptAlgorithmHandle hAlg;
        using SafeBCryptKeyHandle hKey = ImportAesKey(keyDataBlob, headerKeyDataBlob, out hAlg);

        byte[] iv = (byte[])IV.Clone();
        byte[] encryptedTemplate = new byte[plaintextTemplate.Length + 16]; // padding

        int status = BCryptEncrypt(hKey, plaintextTemplate, plaintextTemplate.Length, IntPtr.Zero, iv, iv.Length, encryptedTemplate, encryptedTemplate.Length, out int resultSize, BCRYPT_BLOCK_PADDING);
        if (status != 0)
            throw new Exception($"BCryptEncrypt failed: 0x{status:X}");

        Array.Resize(ref encryptedTemplate, resultSize);
        return encryptedTemplate;
    }

    public static byte[] DecryptTemplate(byte[] IV, byte[] keyDataBlob, BCRYPT_KEY_DATA_BLOB_HEADER headerKeyDataBlob, byte[] encryptedTemplate)
    {
        SafeBCryptAlgorithmHandle hAlg;
        using SafeBCryptKeyHandle hKey = ImportAesKey(keyDataBlob, headerKeyDataBlob, out hAlg);

        byte[] iv = (byte[])IV.Clone();
        byte[] plaintextTemplate = new byte[encryptedTemplate.Length];

        int status = BCryptDecrypt(hKey, encryptedTemplate, encryptedTemplate.Length, IntPtr.Zero, iv, iv.Length, plaintextTemplate, plaintextTemplate.Length, out int resultSize, BCRYPT_BLOCK_PADDING);
        if (status != 0)
            throw new Exception($"BCryptDecrypt failed: 0x{status:X}");

        Array.Resize(ref plaintextTemplate, resultSize);
        return plaintextTemplate;
    }

    #endregion
}
