using AntiSpam.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public sealed class TextAnalyzer : ITextAnalyzer
    {
        private static readonly Regex UrlRegex = new(@"https?://|www\.", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex PhoneRegex = new(@"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b", RegexOptions.Compiled);
        private static readonly Regex WhatsAppRegex = new(@"whats\s*app|wa\.me/\d+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly string[] SpamLexicon = new[]
        {
            "free", "win", "winner", "credit", "loan", "guarantee", "click", "offer",
            "promo", "sex", "adult", "bet", "casino", "crypto", "airdrop", "nude",
            "prize", "congratulations", "bonus", "discount", "limited", "urgent", "act now",
            "subscribe", "follower", "dm", "cash", "money", "earn", "profit", "investment"
        };

        private static readonly Regex ObfuscationRegex =
            new(@"[a@4][i!1l|][gq9][r][a@4]|cl[i1]ck|fr[e3]{2}|0ffer|w[i1]n+\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public Task<TextAnalysisResult> AnalyzeAsync(TextAnalysisInput input, CancellationToken ct = default)
        {
            var text = input.text?.Trim() ?? string.Empty;
            var tokens = Tokenize(text);
            int tokenCount = Math.Max(tokens.Count, 1);

            int urlHits = UrlRegex.Matches(text).Count;
            int spamHits = tokens.Count(t => SpamLexicon.Contains(t, StringComparer.OrdinalIgnoreCase));
            int upperTokens = tokens.Count(t => t.Length > 1 && t.All(char.IsUpper));

            int repeatedRun = MaxRepeatedCharRun(text);
            double entropy = BitsPerCharEntropy(text);

            bool hasPhone = PhoneRegex.IsMatch(text);
            bool hasWA = WhatsAppRegex.IsMatch(text);
            bool obfuscated = ObfuscationRegex.IsMatch(text);

            var result = new TextAnalysisResult(
                UrlRatio: urlHits / (double)tokenCount,
                SpamWordRatio: spamHits / (double)tokenCount,
                UppercaseRatio: upperTokens / (double)tokenCount,
                RepeatedCharMaxRun: repeatedRun,
                EntropyBitsPerChar: entropy,
                ContainsPhoneOrWhatsApp: hasPhone || hasWA,
                ContainsObfuscatedWords: obfuscated,
                TokenCount: tokenCount
            );

            return Task.FromResult(result);
        }

        private static List<string> Tokenize(string text) =>
            Regex.Matches(text.ToLowerInvariant(), @"[a-z0-9@#]+").Select(m => m.Value).ToList();

        private static int MaxRepeatedCharRun(string s)
        {
            int max = 1, cur = 1;
            for (int i = 1; i < s.Length; i++)
            {
                if (s[i] == s[i - 1]) cur++;
                else { if (cur > max) max = cur; cur = 1; }
            }
            return Math.Max(max, cur);
        }

        private static double BitsPerCharEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = s.GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count() / (double)s.Length);
            double h = 0;
            foreach (var p in freq.Values) h += -p * Math.Log(p, 2);
            return h;
        }
    }
}
