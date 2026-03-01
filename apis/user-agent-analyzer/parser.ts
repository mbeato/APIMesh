// Basic browser / OS detector. Pure Bun/JS; no dependencies.
// Returns: { browser: { name, version }, os: { name, version }, deviceType, mobile, bot, raw }
// (browser, os) = 'unknown' if can't guess.

export interface UserAgentResult {
  browser: {
    name: string;
    version: string | null;
  };
  os: {
    name: string;
    version: string | null;
  };
  deviceType: "desktop" | "mobile" | "tablet" | "bot" | "unknown";
  mobile: boolean;
  bot: boolean;
  raw: string;
}

const BROWSER_REGEXES: Array<{ name: string; regex: RegExp; versionGroup?: number }> = [
  // Order matters! (from most to least specific)
  { name: "Edge", regex: /(Edg|Edge|EdgiOS|EdgA)\/([\d.]+)/, versionGroup: 2 },
  { name: "Opera", regex: /(OPR|Opera)\/([\d.]+)/, versionGroup: 2 },
  { name: "Chrome", regex: /Chrome\/([\d.]+)/, versionGroup: 1 },
  { name: "Firefox", regex: /Firefox\/([\d.]+)/, versionGroup: 1 },
  { name: "Safari", regex: /Version\/([\d.]+).*Safari/, versionGroup: 1 },
  { name: "IE", regex: /MSIE\s([\d.]+)/, versionGroup: 1 },
  { name: "IE", regex: /Trident\/.*rv:([\d.]+)/, versionGroup: 1 },
];

const OS_REGEXES: Array<{ name: string; regex: RegExp; versionGroup?: number }> = [
  { name: "Windows", regex: /Windows NT ([\d.]+)/, versionGroup: 1 },
  { name: "macOS", regex: /Mac OS X ([\d_]+)/, versionGroup: 1 },
  { name: "iOS", regex: /iPhone.*OS ([\d_]+)/, versionGroup: 1 },
  { name: "iOS", regex: /iPad.*OS ([\d_]+)/, versionGroup: 1 },
  { name: "Android", regex: /Android ([\d.]+)/, versionGroup: 1 },
  { name: "Linux", regex: /Linux/, versionGroup: undefined },
  { name: "Chrome OS", regex: /CrOS/, versionGroup: undefined },
];

const BOT_REGEXES: RegExp[] = [
  /bot/i,
  /crawler/i,
  /spider/i,
  /facebookexternalhit/i,
  /bingpreview/i,
  /slurp/i,
  /duckduckbot/i,
  /yandex/i,
  /embedly/i,
  /pinterest/i,
  /discordbot/i,
  /telegrambot/i,
  /whatsapp/i,
  /applebot/i,
  /google-structured-data-testing-tool/i,
];

const MOBILE_REGEXES: RegExp[] = [
  /Mobi/i,
  /Android/i,
  /iPhone/i,
  /iPad/i,
  /Phone/i,
  /Mobile/i,
];

const TABLET_REGEXES: RegExp[] = [
  /Tablet/i,
  /iPad/i,
];

export function analyzeUserAgent(ua: string): UserAgentResult {
  // Browser
  let browserName = "unknown", browserVersion: string | null = null;
  for (const { name, regex, versionGroup } of BROWSER_REGEXES) {
    const m = ua.match(regex);
    if (m) {
      browserName = name;
      if (typeof versionGroup === "number" && m[versionGroup]) {
        browserVersion = m[versionGroup].replace(/_/g, ".");
      } else if (m[1]) {
        browserVersion = m[1].replace(/_/g, ".");
      }
      break;
    }
  }

  // OS
  let osName = "unknown", osVersion: string | null = null;
  for (const { name, regex, versionGroup } of OS_REGEXES) {
    const m = ua.match(regex);
    if (m) {
      osName = name;
      if (typeof versionGroup === "number" && m[versionGroup]) {
        osVersion = m[versionGroup].replace(/_/g, ".");
      } else if (name === "Linux" || name === "Chrome OS") {
        osVersion = null;
      }
      break;
    }
  }

  // Bot?
  let bot = false;
  for (const botRx of BOT_REGEXES) {
    if (botRx.test(ua)) { bot = true; break; }
  }

  // Mobile/Tablet?
  let tablet = false;
  let mobile = false;
  for (const tabRx of TABLET_REGEXES) {
    if (tabRx.test(ua)) { tablet = true; break; }
  }
  if (!tablet) {
    for (const mobRx of MOBILE_REGEXES) {
      if (mobRx.test(ua)) { mobile = true; break; }
    }
  }

  let deviceType: "desktop" | "mobile" | "tablet" | "bot" | "unknown" = "unknown";
  if (bot) deviceType = "bot";
  else if (tablet) deviceType = "tablet";
  else if (mobile) deviceType = "mobile";
  else if (browserName !== "unknown" && osName !== "unknown") deviceType = "desktop";

  return {
    browser: {
      name: browserName,
      version: browserVersion,
    },
    os: {
      name: osName,
      version: osVersion,
    },
    deviceType,
    mobile: deviceType === "mobile" || deviceType === "tablet",
    bot,
    raw: ua,
  };
}
