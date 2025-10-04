using AntiSpam.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public sealed class ImageAnalyzer : IImageAnalyzer
    {
        private readonly IOcrService _ocrService;
        private static readonly Regex UrlOrHandle = new(@"https?://|www\.|@\w+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public ImageAnalyzer(IOcrService ocrService)
        {
            _ocrService = ocrService;
        }

        public async Task<ImageAnalysisResult> AnalyzeAsync(ImageAnalysisInput input, CancellationToken ct = default)
        {
            var bytes = input.imageBytes ?? Array.Empty<byte>();
            var size = bytes.Length;

            string sha256;
            using (var sha = SHA256.Create())
                sha256 = Convert.ToHexString(sha.ComputeHash(bytes));

            bool tiny = size < 5_000;
            var text = await _ocrService.ExtractTextAsync(bytes, ct);
            bool ocrHasUrls = UrlOrHandle.IsMatch(text);
            double ocrSpamWordRatio = SpamWordRatio(text);


            return new ImageAnalysisResult(
                IsTinyOrWeirdAspect: tiny,
                HighCompressionOrSuspiciousFormat: false,
                ContentHash: sha256,
                ByteSize: size,
                OcrContainsUrlsOrHandles: ocrHasUrls,
                OcrSpamWordRatio: ocrSpamWordRatio,
                ExtractedText: text
            );
        }

        private static double SpamWordRatio(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return 0;
            var words = Regex.Matches(text.ToLowerInvariant(), @"[a-z0-9]+");
            if (words.Count == 0) return 0;
            string[] lex = { 
                "promo", "discount", "follow", "like", "subscribe", "dm", "whatsapp", "bet",
                "free", "win", "prize", "bonus", "click", "offer", "urgent", "limited",
                "cash", "money", "earn", "profit", "guarantee"
            };
            int hits = words.Cast<System.Text.RegularExpressions.Match>()
                            .Select(m => m.Value)
                            .Count(w => lex.Contains(w));
            return hits / (double)words.Count;
        }
    }
}
