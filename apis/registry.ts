import { app as webChecker } from "./web-checker/index";
import { app as httpStatusChecker } from "./http-status-checker/index";
import { app as faviconChecker } from "./favicon-checker/index";
import { app as microserviceHealthCheck } from "./microservice-health-check/index";
import { app as statusCodeChecker } from "./status-code-checker/index";
import { app as regexBuilder } from "./regex-builder/index";
import { app as userAgentAnalyzer } from "./user-agent-analyzer/index";
import { app as robotsTxtParser } from "./robots-txt-parser/index";
import { app as mockJwtGenerator } from "./mock-jwt-generator/index";
import { app as yamlValidator } from "./yaml-validator/index";
import { app as swaggerDocsCreator } from "./swagger-docs-creator/index";
import { app as coreWebVitals } from "./core-web-vitals/index";
import { app as securityHeaders } from "./security-headers/index";
import { app as redirectChain } from "./redirect-chain/index";
import { app as emailSecurity } from "./email-security/index";
import { app as seoAudit } from "./seo-audit/index";
import { app as indexability } from "./indexability/index";
import { app as brandAssets } from "./brand-assets/index";
import { app as emailVerify } from "./email-verify/index";
import { app as techStack } from "./tech-stack/index";
import { app as webResourceValidator } from "./web-resource-validator/index";
import { app as websiteSecurityHeaderInfo } from "./website-security-header-info/index";
import { app as websiteVulnerabilityScan } from "./website-vulnerability-scan/index";
import { app as agentcontext } from "./agentcontext/index";
import { app as sigdebug } from "./sigdebug/index";
import type { Hono } from "hono";
import { app as subdomainVulnerabilityRankings } from "./subdomain-vulnerability-rankings/index";
import { app as cspPolicyHeuristics } from "./csp-policy-heuristics/index";
import { app as sslTlsRiskAnalyzer } from "./ssl-tls-risk-analyzer/index";
import { app as subdomainVulnerabilityRanking } from "./subdomain-vulnerability-ranking/index";
import { app as subdomainExposureScore } from "./subdomain-exposure-score/index";
import { app as ipInfrastructureAnalyst } from "./ip-infrastructure-analyst/index";
import { app as subdomainExposureScorer } from "./subdomain-exposure-scorer/index";
import { app as sslTlsThreatAssessment } from "./ssl-tls-threat-assessment/index";
import { app as privacyPolicyQualify } from "./privacy-policy-qualify/index";
import { app as dnsPropagationMapper } from "./dns-propagation-mapper/index";
import { app as ipInfrastructureAnalyzer } from "./ip-infrastructure-analyzer/index";
import { app as ipGeolocationEnrichment } from "./ip-geolocation-enrichment/index";
import { app as websiteAuthenticityAssessment } from "./website-authenticity-assessment/index";
import { app as sslAndTlsHardeningScore } from "./ssl-and-tls-hardening-score/index";
import { app as securityHeadersChecker } from "./security-headers-checker/index";
import { app as subdomainExposureRanking } from "./subdomain-exposure-ranking/index";
import { app as sslTlsHardeningForecast } from "./ssl-tls-hardening-forecast/index";
import { app as subdomainExposureRankings } from "./subdomain-exposure-rankings/index";
import { app as sslTlsExpiryForecast } from "./ssl-tls-expiry-forecast/index";
import { app as networkRouteMapper } from "./network-route-mapper/index";
import { app as subdomainExposureHeatmap } from "./subdomain-exposure-heatmap/index";
import { app as dnsPropagationSimulator } from "./dns-propagation-simulator/index";
import { app as sslTlsConfigurationRanker } from "./ssl-tls-configuration-ranker/index";
import { app as privacyPolicyEnricher } from "./privacy-policy-enricher/index";
import { app as privacyRiskScore } from "./privacy-risk-score/index";
import { app as httpMethodEnumeration } from "./http-method-enumeration/index";
import { app as webMisconfigurationScan } from "./web-misconfiguration-scan/index";
import { app as dependencyLicenseAudit } from "./dependency-license-audit/index";
import { app as sslTlsConfigurationForecast } from "./ssl-tls-configuration-forecast/index";
import { app as subdomainRiskRanking } from "./subdomain-risk-ranking/index";
import { app as contentShuffleDetector } from "./content-shuffle-detector/index";
import { app as apiSchemaDiff } from "./api-schema-diff/index";
import { app as apiLinting } from "./api-linting/index";
import { app as portScannerAggregate } from "./port-scanner-aggregate/index";
import { app as cdnInfrastructureEnricher } from "./cdn-infrastructure-enricher/index";
import { app as webConfigurationAudit } from "./web-configuration-audit/index";
import { app as subdomainVulnerabilityRanker } from "./subdomain-vulnerability-ranker/index";
import { app as sslTlsInceptionScore } from "./ssl-tls-inception-score/index";
import { app as dnsPropagationHeatmap } from "./dns-propagation-heatmap/index";
import { app as apiSchemaDelta } from "./api-schema-delta/index";
import { app as portScanner } from "./port-scanner/index";
import { app as sslTlsHardeningAssessor } from "./ssl-tls-hardening-assessor/index";
import { app as performanceSecurityComplianceReport } from "./performance-security-compliance-report/index";
import { app as sslExpiryForecast } from "./ssl-expiry-forecast/index";
import { app as apiResponseHeuristics } from "./api-response-heuristics/index";
import { app as contentSecurityPolicyCheck } from "./content-security-policy-check/index";
import { app as apiEndpointDiscovery } from "./api-endpoint-discovery/index";
import { app as siteSecurityBaseline } from "./site-security-baseline/index";
import { app as dnsPropagationInspector } from "./dns-propagation-inspector/index";
import { app as crossOriginResourcePolicymapper } from "./cross-origin-resource-policymapper/index";
import { app as apiStandardCompliance } from "./api-standard-compliance/index";
import { app as subdomainResilienceScore } from "./subdomain-resilience-score/index";
import { app as sslConfigurationRank } from "./ssl-configuration-rank/index";
import { app as dnsChangeForecast } from "./dns-change-forecast/index";
import { app as networkPathInfer } from "./network-path-infer/index";
import { app as websiteCspViolationReport } from "./website-csp-violation-report/index";
import { app as apiTechnologyHeaders } from "./api-technology-headers/index";
import { app as apiStructureValidator } from "./api-structure-validator/index";
import { app as apiEndpointHeuristics } from "./api-endpoint-heuristics/index";
import { app as apiEndpointDisclosure } from "./api-endpoint-disclosure/index";
import { app as pagePerformanceMetrics } from "./page-performance-metrics/index";
import { app as subdomainEnumAggregator } from "./subdomain-enum-aggregator/index";
import { app as sslTlsProtocolCompliance } from "./ssl-tls-protocol-compliance/index";
import { app as apiEndpointDiscoveryGraph } from "./api-endpoint-discovery-graph/index";
import { app as subdomainConfigurationEntropy } from "./subdomain-configuration-entropy/index";
import { app as privacyPolicyDiff } from "./privacy-policy-diff/index";
import { app as networkPathHeatmap } from "./network-path-heatmap/index";
import { app as sslTlsVulnerabilityAssessment } from "./ssl-tls-vulnerability-assessment/index";
import { app as webConfigurationFingerprint } from "./web-configuration-fingerprint/index";










































































export const registry: Record<string, Hono> = {
  "check": webChecker,
  "http-status-checker": httpStatusChecker,
  "favicon-checker": faviconChecker,
  "microservice-health-check": microserviceHealthCheck,
  "status-code-checker": statusCodeChecker,
  "regex-builder": regexBuilder,
  "user-agent-analyzer": userAgentAnalyzer,
  "robots-txt-parser": robotsTxtParser,
  "mock-jwt-generator": mockJwtGenerator,
  "yaml-validator": yamlValidator,
  "swagger-docs-creator": swaggerDocsCreator,
  "core-web-vitals": coreWebVitals,
  "security-headers": securityHeaders,
  "redirect-chain": redirectChain,
  "email-security": emailSecurity,
  "seo-audit": seoAudit,
  "indexability": indexability,
  "brand-assets": brandAssets,
  "email-verify": emailVerify,
  "tech-stack": techStack,
  "web-resource-validator": webResourceValidator,
  "website-security-header-info": websiteSecurityHeaderInfo,
  "website-vulnerability-scan": websiteVulnerabilityScan,
  "subdomain-vulnerability-rankings": subdomainVulnerabilityRankings,
  "csp-policy-heuristics": cspPolicyHeuristics,
  "ssl-tls-risk-analyzer": sslTlsRiskAnalyzer,
  "subdomain-vulnerability-ranking": subdomainVulnerabilityRanking,
  "subdomain-exposure-score": subdomainExposureScore,
  "ip-infrastructure-analyst": ipInfrastructureAnalyst,
  "subdomain-exposure-scorer": subdomainExposureScorer,
  "ssl-tls-threat-assessment": sslTlsThreatAssessment,
  "privacy-policy-qualify": privacyPolicyQualify,
  "dns-propagation-mapper": dnsPropagationMapper,
  "ip-infrastructure-analyzer": ipInfrastructureAnalyzer,
  "ip-geolocation-enrichment": ipGeolocationEnrichment,
  "website-authenticity-assessment": websiteAuthenticityAssessment,
  "ssl-and-tls-hardening-score": sslAndTlsHardeningScore,
  "security-headers-checker": securityHeadersChecker,
  "subdomain-exposure-ranking": subdomainExposureRanking,
  "ssl-tls-hardening-forecast": sslTlsHardeningForecast,
  "subdomain-exposure-rankings": subdomainExposureRankings,
  "ssl-tls-expiry-forecast": sslTlsExpiryForecast,
  "network-route-mapper": networkRouteMapper,
  "subdomain-exposure-heatmap": subdomainExposureHeatmap,
  "dns-propagation-simulator": dnsPropagationSimulator,
  "ssl-tls-configuration-ranker": sslTlsConfigurationRanker,
  "privacy-policy-enricher": privacyPolicyEnricher,
  "privacy-risk-score": privacyRiskScore,
  "http-method-enumeration": httpMethodEnumeration,
  "web-misconfiguration-scan": webMisconfigurationScan,
  "dependency-license-audit": dependencyLicenseAudit,
  "ssl-tls-configuration-forecast": sslTlsConfigurationForecast,
  "subdomain-risk-ranking": subdomainRiskRanking,
  "content-shuffle-detector": contentShuffleDetector,
  "api-schema-diff": apiSchemaDiff,
  "api-linting": apiLinting,
  "port-scanner-aggregate": portScannerAggregate,
  "cdn-infrastructure-enricher": cdnInfrastructureEnricher,
  "web-configuration-audit": webConfigurationAudit,
  "subdomain-vulnerability-ranker": subdomainVulnerabilityRanker,
  "ssl-tls-inception-score": sslTlsInceptionScore,
  "dns-propagation-heatmap": dnsPropagationHeatmap,
  "api-schema-delta": apiSchemaDelta,
  "port-scanner": portScanner,
  "ssl-tls-hardening-assessor": sslTlsHardeningAssessor,
  "performance-security-compliance-report": performanceSecurityComplianceReport,
  "ssl-expiry-forecast": sslExpiryForecast,
  "api-response-heuristics": apiResponseHeuristics,
  "content-security-policy-check": contentSecurityPolicyCheck,
  "api-endpoint-discovery": apiEndpointDiscovery,
  "site-security-baseline": siteSecurityBaseline,
  "dns-propagation-inspector": dnsPropagationInspector,
  "cross-origin-resource-policymapper": crossOriginResourcePolicymapper,
  "api-standard-compliance": apiStandardCompliance,
  "subdomain-resilience-score": subdomainResilienceScore,
  "ssl-configuration-rank": sslConfigurationRank,
  "dns-change-forecast": dnsChangeForecast,
  "network-path-infer": networkPathInfer,
  "website-csp-violation-report": websiteCspViolationReport,
  "api-technology-headers": apiTechnologyHeaders,
  "api-structure-validator": apiStructureValidator,
  "api-endpoint-heuristics": apiEndpointHeuristics,
  "api-endpoint-disclosure": apiEndpointDisclosure,
  "page-performance-metrics": pagePerformanceMetrics,
  "subdomain-enum-aggregator": subdomainEnumAggregator,
  "ssl-tls-protocol-compliance": sslTlsProtocolCompliance,
  "api-endpoint-discovery-graph": apiEndpointDiscoveryGraph,
  "subdomain-configuration-entropy": subdomainConfigurationEntropy,
  "agentsmd": agentcontext,
  "agentcontext": agentcontext,
  "stripesig": sigdebug,
  "sigdebug": sigdebug,
  "privacy-policy-diff": privacyPolicyDiff,
  "network-path-heatmap": networkPathHeatmap,
  "ssl-tls-vulnerability-assessment": sslTlsVulnerabilityAssessment,
  "web-configuration-fingerprint": webConfigurationFingerprint,
};
