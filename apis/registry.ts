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
import type { Hono } from "hono";

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
};
