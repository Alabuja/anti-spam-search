using AntiSpam.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public interface ITextAnalyzer
    {
        Task<TextAnalysisResult> AnalyzeAsync(TextAnalysisInput input, CancellationToken ct = default);
    }

    public interface IImageAnalyzer
    {
        Task<ImageAnalysisResult> AnalyzeAsync(ImageAnalysisInput input, CancellationToken ct = default);
    }

    public interface IBehaviorAnalyzer
    {
        Task<BehaviorAnalysisResult> AnalyzeAsync(BehaviorAnalysisInput input, CancellationToken ct = default);
    }

    public interface ISpamScoringService
    {
        Task<SpamDecision> ScoreAsync(SpamEvidence evidence, CancellationToken ct = default);
    }

    public interface IOcrService
    {
        Task<string> ExtractTextAsync(byte[] imageBytes, CancellationToken ct = default);
    }
}
