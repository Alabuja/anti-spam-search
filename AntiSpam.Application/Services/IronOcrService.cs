using AntiSpam.Application.Dtos;
using IronOcr;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public sealed class IronOcrService : IOcrService
    {
        private readonly OcrOptions _options;
        private readonly ILogger<IronOcrService> _logger;

        public IronOcrService(
            OcrOptions options,
            ILogger<IronOcrService> logger
            )
        {
            _options = options;
            _logger = logger;
        }

        public async Task<string> ExtractTextAsync(byte[] imageBytes, CancellationToken ct = default)
        {
            try
            {
                var ocr = new IronTesseract();
                
                if (!string.IsNullOrEmpty(_options.Language))
                {
                    // Map language code to IronOcr language
                    ocr.Language = MapLanguage(_options.Language);
                    var message = $"OCR Language set to {_options.Language} ({ocr.Language})";
                    _logger.LogInformation(message);
                }

                ocr.Configuration.ReadBarCodes = false; // Disable barcode reading for performance
                ocr.Configuration.TesseractVersion = TesseractVersion.Tesseract5;

                using var input = new OcrInput();
                input.LoadImage(imageBytes);
                
                var result = await Task.Run(() => ocr.Read(input), ct);
                
                var extractedText = result.Text ?? string.Empty;
                Console.WriteLine();
                var extractedTextLength = $"Extracted text length: {extractedText.Length} characters";
                _logger.LogInformation(extractedTextLength);

                return extractedText;
            }
            catch (Exception ex)
            {
                var exception = $"IronOCR processing failed: {ex.Message}";
                _logger.LogInformation(exception);
                throw new InvalidOperationException(exception, ex);
            }
        }

        private OcrLanguage MapLanguage(string languageCode)
        {
            // Map common language codes to IronOcr.OcrLanguage enum
            return languageCode.ToLowerInvariant() switch
            {
                "eng" or "en" => OcrLanguage.English,
                "spa" or "es" => OcrLanguage.Spanish,
                "fra" or "fr" => OcrLanguage.French,
                "deu" or "de" => OcrLanguage.German,
                "ita" or "it" => OcrLanguage.Italian,
                "por" or "pt" => OcrLanguage.Portuguese,
                "rus" or "ru" => OcrLanguage.Russian,
                "chi_sim" or "zh" or "zh-cn" => OcrLanguage.ChineseSimplified,
                "chi_tra" or "zh-tw" => OcrLanguage.ChineseTraditional,
                "jpn" or "ja" => OcrLanguage.Japanese,
                "kor" or "ko" => OcrLanguage.Korean,
                "ara" or "ar" => OcrLanguage.Arabic,
                "hin" or "hi" => OcrLanguage.Hindi,
                _ => OcrLanguage.English // Default to English for unsupported languages
            };
        }
    }
}
