using AntiSpam.Application.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Dtos
{
    public sealed record TextAnalysisInput(string text, string? LanguageHint = null);
    public sealed record ImageAnalysisInput(byte[] imageBytes, string? ocrText = null, string? mimeType = null);
    public sealed record BehaviorEvent(DateTimeOffset timestamp, string kind, string ipHash, string deviceId, int payloadSize);
    public sealed record BehaviorAnalysisInput(string userId, IReadOnlyList<BehaviorEvent> events, TimeSpan lookback);

    public sealed record TextAnalysisResult(
        double UrlRatio,
        double SpamWordRatio,
        double UppercaseRatio,
        int RepeatedCharMaxRun,
        double EntropyBitsPerChar,
        bool ContainsPhoneOrWhatsApp,
        bool ContainsObfuscatedWords,
        int TokenCount);

    public sealed record ImageAnalysisResult(
        bool IsTinyOrWeirdAspect,
        bool HighCompressionOrSuspiciousFormat,
        string ContentHash,
        int ByteSize,
        bool OcrContainsUrlsOrHandles,
        double OcrSpamWordRatio,
        string? ExtractedText);

    public sealed record BehaviorAnalysisResult(
        double Burstiness,
        double RepetitionScore,
        double NewAccountRisk,
        double IpRotationRate,
        double DeviceRotationRate,
        double NightActivityBias
    );

    public sealed record SpamEvidence(
        TextAnalysisResult? Text,
        ImageAnalysisResult? Image,
        BehaviorAnalysisResult? Behavior);

    public sealed record SpamDecision(
        SpamVerdict Verdict,
        double Score,
        IReadOnlyList<string> Reasons);

    public sealed record CombinedAnalyzeRequest(
            string? Text,
            string? ImageBase64,
            string? ImageMimeType,
            string? ImageOcrText,
            string UserId,
            List<BehaviorEvent>? Events,
            double LookbackHours = 24
        );

    public sealed record ImageAnalyzeRequest(string? OcrText = null, string? MimeType = null);

    public sealed class OcrOptions
    {
        public string Engine { get; set; } = "tesseract";
        public string Language { get; set; } = "eng";     // e.g., "eng", "eng+fra"
    }

}
