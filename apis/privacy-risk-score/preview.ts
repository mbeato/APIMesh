import type { PreviewResponse } from "./types";
import { validateExternalUrl, safeFetch } from "../../shared/ssrf";

export async function previewAnalysis(rawUrl: string): Promise<PreviewResponse | { error: string }> {
  const check = validateExternalUrl(rawUrl);
  if ("error" in check) return { error: check.error };

  const url = check.url;
  const domain = url.hostname;

  try {
    const res = await safeFetch(url.toString(), {
      method: "GET",
      signal: AbortSignal.timeout(15000),
      headers: { "User-Agent": "privacy-risk-score-preview/1.0 apimesh.xyz" },
    });

    const text = await res.text();
    const snippet = text.slice(0, 2048).replace(/\s+/g, " ").trim();

    const summary = `Fetched homepage for ${domain}. Content length: ${text.length} chars. Basic preview shows initial content snippet and checks for GDPR/CCPA keywords.`;

    // Optionally extract simple compliance signals for preview
    // Check simple presence
    const lowerText = snippet.toLowerCase();
    const gdprDetected = lowerText.includes("gdpr") || lowerText.includes("general data protection regulation");
    const ccpaDetected = lowerText.includes("ccpa") || lowerText.includes("california consumer privacy act");

    const compliance = {
      gdprDetected,
      gdprScore: gdprDetected ? 50 : 0,
      ccpaDetected,
      ccpaScore: ccpaDetected ? 50 : 0,
      dataSharingCount: 0,
    };

    return {
      domain,
      fetchedUrl: res.url,
      preview: true,
      summary,
      compliance,
      note: "Preview is free and shows minimal info with basic keyword scanning. Payment unlocks detailed multi-source privacy risk scoring.",
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status = /timeout|timed out|abort/i.test(msg) ? 504 : 502;
    return { error: `Analysis temporarily unavailable: ${msg}` };
  }
}
