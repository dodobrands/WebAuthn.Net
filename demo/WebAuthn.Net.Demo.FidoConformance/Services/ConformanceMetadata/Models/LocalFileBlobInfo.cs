namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata.Models;

public class LocalFileBlobInfo
{
    public LocalFileBlobInfo(string fileName, string content)
    {
        FileName = fileName;
        Content = content;
    }

    public string FileName { get; }

    public string Content { get; }
}
