using AntiSpam.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public sealed class BehaviorAnalyzer : IBehaviorAnalyzer
    {
        public Task<BehaviorAnalysisResult> AnalyzeAsync(BehaviorAnalysisInput input, CancellationToken ct = default)
        {
            var events = input.events?.OrderBy(e => e.timestamp).ToList() ?? new();
            if (events.Count == 0)
                return Task.FromResult(new BehaviorAnalysisResult(0, 0, 0, 0, 0, 0));

            return Task.FromResult(Calc(input, events));
        }

        private static BehaviorAnalysisResult Calc(BehaviorAnalysisInput input, List<BehaviorEvent> events)
        {
            double avgPerMin = events.Count / Math.Max(1.0, input.lookback.TotalMinutes);
            double maxPerMinWindow = MaxWindowCount(events, TimeSpan.FromMinutes(1));
            double burstiness = avgPerMin > 0 ? maxPerMinWindow / avgPerMin : 0;

            double repetition = RepetitionScore(events);

            double newAcc = (input.lookback.TotalDays < 3 && events.Count > 30) ? 0.9
                          : (input.lookback.TotalDays < 7 && events.Count > 100) ? 0.6
                          : 0.1;

            double ipRotation = events
                .GroupBy(e => e.timestamp.Date)
                .DefaultIfEmpty()
                .Average(g => g?.Select(x => x.ipHash).Distinct().Count() ?? 0);

            double deviceRotation = events
                .GroupBy(e => e.timestamp.Date)
                .DefaultIfEmpty()
                .Average(g => g?.Select(x => x.deviceId).Distinct().Count() ?? 0);

            double nightShare = events.Count(e => e.timestamp.Hour is >= 0 and < 4) / (double)events.Count;

            return new BehaviorAnalysisResult(
                Burstiness: burstiness,
                RepetitionScore: repetition,
                NewAccountRisk: newAcc,
                IpRotationRate: ipRotation,
                DeviceRotationRate: deviceRotation,
                NightActivityBias: nightShare
            );
        }

        private static double MaxWindowCount(List<BehaviorEvent> evts, TimeSpan window)
        {
            int max = 0, j = 0;
            for (int i = 0; i < evts.Count; i++)
            {
                var start = evts[i].timestamp;
                while (j < evts.Count && evts[j].timestamp - start <= window) j++;
                max = Math.Max(max, j - i);
            }
            return max;
        }

        private static double RepetitionScore(List<BehaviorEvent> evts)
        {
            var groups = evts.GroupBy(e => (e.kind, Bucket(e.payloadSize)));
            var top = groups.Select(g => g.Count()).DefaultIfEmpty(0).Max();
            return top / Math.Sqrt(Math.Max(1, evts.Count));
        }

        private static int Bucket(int size) => size switch
        {
            < 256 => 0,
            < 1024 => 1,
            < 4096 => 2,
            < 16384 => 3,
            _ => 4
        };
    }
}
