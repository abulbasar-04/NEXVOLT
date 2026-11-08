export function hasUnifiedRiskScore(result) {
  return Number.isFinite(result?.risk_score) &&
    Array.isArray(result?.score_explanation?.components) &&
    result.score_explanation.components.length > 0;
}
