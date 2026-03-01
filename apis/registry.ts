import { app as webChecker } from "./web-checker/index";
import type { Hono } from "hono";
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











export const registry: Record<string, Hono> = {
  check: webChecker,
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
};
