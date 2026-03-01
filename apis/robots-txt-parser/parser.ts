export interface RobotsTxtRecord {
  userAgents: string[];
  allows: string[];
  disallows: string[];
  crawlDelay?: number;
  sitemaps: string[];
  host?: string;
  rawLines: string[];
}

export interface RobotsTxtParsed {
  records: RobotsTxtRecord[];
  sitemaps: string[];
  hosts: string[];
  rawLength: number;
}

export interface RobotsTxtAnalysis {
  agents: {
    name: string;
    allows?: number;
    disallows?: number;
    crawlDelay?: number;
    isGlobal: boolean;
    notes?: string[];
  }[];
  hasSitemap: boolean;
  hasHost: boolean;
  wellFormed: boolean;
  anomalies: string[];
  summary: string;
}

/**
 * Basic parser for robots.txt per record section
 * @param lines lines of robots.txt
 */
export function parseRobotsTxt(lines: string[]): RobotsTxtParsed {
  const records: RobotsTxtRecord[] = [];
  let currentAgents: string[] = [];
  let currentAllows: string[] = [];
  let currentDisallows: string[] = [];
  let currentCrawlDelay: number | undefined = undefined;
  let currentSitemaps: string[] = [];
  let currentHost: string | undefined = undefined;
  let recordRaw: string[] = [];

  // non-agent section sitemaps/host
  const globalSitemaps: string[] = [];
  const globalHosts: string[] = [];

  const pushRecord = () => {
    if (currentAgents.length === 0 && (currentAllows.length > 0 || currentDisallows.length > 0 || currentCrawlDelay != null)) {
      currentAgents = ["*"];
    }
    if (currentAgents.length > 0) {
      records.push({
        userAgents: currentAgents.slice(),
        allows: currentAllows.slice(),
        disallows: currentDisallows.slice(),
        crawlDelay: currentCrawlDelay,
        sitemaps: currentSitemaps.slice(),
        host: currentHost,
        rawLines: recordRaw.slice(),
      });
      currentAgents = [];
      currentAllows = [];
      currentDisallows = [];
      currentCrawlDelay = undefined;
      currentSitemaps = [];
      currentHost = undefined;
      recordRaw = [];
    }
  };

  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith("#")) continue; // ignore blanks and comments
    let ix = line.indexOf(":");
    if (ix === -1) continue;
    let field = line.slice(0, ix).trim().toLowerCase();
    let value = line.slice(ix + 1).trim();
    recordRaw.push(rawLine);

    switch (field) {
      case "user-agent":
        if (currentAgents.length > 0 || currentAllows.length > 0 || currentDisallows.length > 0 || currentCrawlDelay !== undefined) {
          pushRecord();
        }
        currentAgents.push(value);
        break;
      case "allow":
        currentAllows.push(value);
        break;
      case "disallow":
        currentDisallows.push(value);
        break;
      case "crawl-delay":
        const valNum = parseFloat(value);
        if (!isNaN(valNum)) currentCrawlDelay = valNum;
        break;
      case "sitemap":
        currentSitemaps.push(value);
        globalSitemaps.push(value);
        break;
      case "host":
        currentHost = value;
        globalHosts.push(value);
        break;
      default:
        // ignore (will appear in rawLines)
        break;
    }
  }
  pushRecord();
  return {
    records,
    sitemaps: globalSitemaps,
    hosts: globalHosts,
    rawLength: lines.length,
  };
}

/**
 * Provides analysis/insights about a parsed robots.txt
 * - Which agents are present?
 * - What is allowed/disallowed for each?
 * - Any anomalies (missing UA, conflicting rules, huge files, etc)?
 * - Are sitemaps exposed?
 */
export function analyzeRobotsTxt(parsed: RobotsTxtParsed): RobotsTxtAnalysis {
  const anomalies: string[] = [];
  const agents: RobotsTxtAnalysis['agents'] = [];
  let globalUAFound = false;

  if (parsed.rawLength > 2000) anomalies.push("Unusually large robots.txt (>2000 lines)");
  if (parsed.records.length === 0) anomalies.push("No user-agent records found");

  for (const rec of parsed.records) {
    for (const ua of rec.userAgents) {
      let isGlobal = ua === "*";
      if (isGlobal) globalUAFound = true;
      const notes = [] as string[];
      if (rec.crawlDelay !== undefined && isNaN(rec.crawlDelay)) {
        notes.push("Crawl-delay is not a valid number");
      } else if (rec.crawlDelay !== undefined && rec.crawlDelay > 60) {
        notes.push("Crawl-delay is unusually high (> 60s)");
      }
      if (rec.allows.length === 0 && rec.disallows.length === 0) {
        notes.push("No allow/disallow rules for this agent.");
      }
      if (rec.allows.includes("/")) notes.push("Explicit allow of all "/".");
      if (rec.disallows.includes("/")) notes.push("Explicitly disallow all (site-wide block). This will block crawling for this agent.");
      agents.push({
        name: ua,
        allows: rec.allows.length,
        disallows: rec.disallows.length,
        crawlDelay: rec.crawlDelay,
        isGlobal,
        notes: notes.length ? notes : undefined
      });
    }
  }

  if (!globalUAFound) anomalies.push("No global ('*') user-agent section present. Consider adding user-agent: * for generic bots.");

  const hasSitemap = parsed.sitemaps.length > 0;
  const hasHost = parsed.hosts.length > 0;
  const wellFormed = !anomalies.length;
  let summary = "";
  if (!parsed.records.length) {
    summary = "No crawling rules found for any user agent. Most bots may assume full access.";
  } else if (!globalUAFound) {
    summary = "Site does not declare a default ('*') user-agent. Some bots may not interpret rules.";
  } else {
    summary = `${parsed.records.length} user-agent sections. ${hasSitemap ? "Sitemap(s) provided." : "No sitemap listed."}`;
  }

  return {
    agents,
    hasSitemap,
    hasHost,
    wellFormed,
    anomalies,
    summary
  };
}
