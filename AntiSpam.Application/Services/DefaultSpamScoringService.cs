using AntiSpam.Application.Dtos;
using AntiSpam.Application.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public class DefaultSpamScoringService : ISpamScoringService
    {
        public Task<SpamDecision> ScoreAsync(SpamEvidence e, CancellationToken ct = default)
        {
            double score = 0;
            var reasons = new List<string>();

            if (e.Text is not null)
            {
                var t = e.Text;
                score += Clamp(100 * t.UrlRatio * 0.9); if (t.UrlRatio > 0.15) reasons.Add("Many URLs");
                score += Clamp(100 * t.SpamWordRatio * 2.5); if (t.SpamWordRatio > 0.05) reasons.Add("Spam lexicon terms");
                score += Clamp(t.RepeatedCharMaxRun * 2); if (t.RepeatedCharMaxRun >= 4) reasons.Add("Character runs");
                score += Clamp((t.UppercaseRatio - 0.3) * 120); if (t.UppercaseRatio > 0.5) reasons.Add("Shouting text");
                score += Clamp((t.EntropyBitsPerChar < 2.5 ? 10 : 0)); if (t.EntropyBitsPerChar < 2.5) reasons.Add("Low entropy (template)");
                if (t.ContainsPhoneOrWhatsApp) { score += 18; reasons.Add("Phone/WhatsApp solicitations"); }
                if (t.ContainsObfuscatedWords) { score += 12; reasons.Add("Obfuscated terms (e.g., v¡agr@)"); }
            }

            if (e.Image is not null)
            {
                var i = e.Image;
                if (i.IsTinyOrWeirdAspect) { score += 10; reasons.Add("Tiny or odd aspect image"); }
                if (i.HighCompressionOrSuspiciousFormat) { score += 8; reasons.Add("Highly compressed image"); }
                if (i.OcrContainsUrlsOrHandles) { score += 20; reasons.Add("Image with URLs/handles (via OCR)"); }
                score += Clamp(100 * i.OcrSpamWordRatio * 1.8);
            }

            if (e.Behavior is not null)
            {
                var b = e.Behavior;
                score += Clamp(b.Burstiness * 20); if (b.Burstiness > 3) reasons.Add("High send burst");
                score += Clamp(b.RepetitionScore * 15); if (b.RepetitionScore > 2) reasons.Add("Repeated content pattern");
                score += Clamp(b.NewAccountRisk * 25); if (b.NewAccountRisk > 0.6) reasons.Add("New account risk");
                score += Clamp(b.IpRotationRate * 12); if (b.IpRotationRate > 3) reasons.Add("Frequent IP rotation");
                score += Clamp(b.DeviceRotationRate * 8); if (b.DeviceRotationRate > 2) reasons.Add("Frequent device rotation");
                score += Clamp((b.NightActivityBias - 0.4) * 30); if (b.NightActivityBias > 0.7) reasons.Add("Odd-hour spikes");
            }

            score = Clamp(score);
            var verdict = score switch
            {
                >= 70 => SpamVerdict.Block,
                >= 40 => SpamVerdict.Review,
                _ => SpamVerdict.Allow
            };

            return Task.FromResult(new SpamDecision(verdict, score, reasons));
        }

        private static double Clamp(double v) => v switch { < 0 => 0, > 100 => 100, _ => v };
    }
}
