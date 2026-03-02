import { Resolver } from "node:dns/promises";

const resolver = new Resolver();
const DNS_TIMEOUT_MS = 3_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EmailVerifyResult {
  email: string;
  domain: string;
  syntax: { valid: boolean; local: string; domain: string };
  mx: { found: boolean; records: { priority: number; hostname: string }[]; acceptsMail: boolean };
  disposable: boolean;
  roleAddress: boolean;
  freeProvider: boolean;
  deliverable: "likely" | "unlikely" | "unknown";
  checkedAt: string;
}

export interface EmailVerifyPreview {
  email: string;
  domain: string;
  syntax: { valid: boolean };
  disposable: boolean;
  roleAddress: boolean;
  freeProvider: boolean;
  checkedAt: string;
}

// ---------------------------------------------------------------------------
// Syntax Validation
// ---------------------------------------------------------------------------

// RFC 5321 compliant (simplified — covers 99.9% of real addresses)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

export function validateSyntax(email: string): { valid: boolean; local: string; domain: string } {
  const trimmed = email.trim().toLowerCase();
  if (!EMAIL_REGEX.test(trimmed)) {
    return { valid: false, local: "", domain: "" };
  }
  const atIdx = trimmed.lastIndexOf("@");
  return {
    valid: true,
    local: trimmed.slice(0, atIdx),
    domain: trimmed.slice(atIdx + 1),
  };
}

// ---------------------------------------------------------------------------
// Role Address Detection
// ---------------------------------------------------------------------------

const ROLE_ADDRESSES = new Set([
  "abuse", "admin", "administrator", "billing", "compliance", "devnull",
  "dns", "ftp", "hostmaster", "info", "inoc", "ispfeedback", "ispsupport",
  "legal", "list", "list-request", "maildaemon", "mailer-daemon", "marketing",
  "media", "noc", "no-reply", "noreply", "noc", "office", "operations",
  "ops", "phishing", "postmaster", "privacy", "registrar", "root",
  "sales", "security", "spam", "support", "sysadmin", "tech",
  "undisclosed-recipients", "unsubscribe", "usenet", "uucp", "webmaster",
  "www",
]);

export function isRoleAddress(local: string): boolean {
  return ROLE_ADDRESSES.has(local.toLowerCase());
}

// ---------------------------------------------------------------------------
// Free Email Provider Detection
// ---------------------------------------------------------------------------

const FREE_PROVIDERS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
  "icloud.com", "mail.com", "zoho.com", "yandex.com", "protonmail.com",
  "proton.me", "tutanota.com", "tuta.com", "gmx.com", "gmx.net",
  "fastmail.com", "hey.com", "live.com", "msn.com", "me.com",
  "mac.com", "yahoo.co.uk", "yahoo.co.jp", "yahoo.fr", "yahoo.de",
  "hotmail.co.uk", "hotmail.fr", "mail.ru", "inbox.com", "aim.com",
  "ymail.com", "rocketmail.com",
]);

export function isFreeProvider(domain: string): boolean {
  return FREE_PROVIDERS.has(domain.toLowerCase());
}

// ---------------------------------------------------------------------------
// Disposable Email Domain Detection
// ---------------------------------------------------------------------------

// Top ~300 most common disposable email domains
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "guerrillamail.de", "guerrillamailblock.com", "grr.la", "sharklasers.com",
  "guerrillamail.info", "tempmail.com", "temp-mail.org", "throwaway.email",
  "yopmail.com", "yopmail.fr", "yopmail.net", "mailnesia.com",
  "tempail.com", "tempr.email", "discard.email", "discardmail.com",
  "discardmail.de", "trashmail.com", "trashmail.me", "trashmail.net",
  "trashmail.org", "trashmail.at", "10minutemail.com", "10minutemail.net",
  "minutemail.com", "getairmail.com", "getnada.com", "nada.email",
  "mailcatch.com", "mailexpire.com", "maildrop.cc", "mailforspam.com",
  "mailhazard.com", "mailhazard.us", "mailinator.net", "mailinator.us",
  "mailinator2.com", "mailmoat.com", "mailnull.com", "mailsac.com",
  "mailscrap.com", "mailshell.com", "mailsiphon.com", "mailslapping.com",
  "mailslite.com", "mailtemp.info", "mailtothis.com", "mailzilla.com",
  "throwawaymail.com", "crazymailing.com", "deadaddress.com", "despammed.com",
  "devnullmail.com", "disposemail.com", "dispostable.com", "emailigo.de",
  "emailisvalid.com", "emailondeck.com", "emailresort.com", "emailsensei.com",
  "emailtemporario.com.br", "emailto.de", "emailwarden.com", "emailx.at.hm",
  "fakeinbox.com", "fakeemail.de", "fakemail.fr", "fastacura.com",
  "filzmail.com", "fixmail.tk", "flyspam.com", "gishpuppy.com",
  "great-host.in", "greensloth.com", "harakirimail.com", "hidemail.de",
  "hulapla.de", "ieatspam.eu", "ieatspam.info", "imails.info",
  "incognitomail.com", "incognitomail.net", "incognitomail.org",
  "ipoo.org", "irish2me.com", "jetable.com", "jetable.fr.nf",
  "jetable.net", "jetable.org", "kasmail.com", "koszmail.pl",
  "kurzepost.de", "letthemeatspam.com", "lhsdv.com", "lifebyfood.com",
  "link2mail.net", "litedrop.com", "lookugly.com", "lortemail.dk",
  "lovemeleaveme.com", "lr78.com", "maileater.com", "mailbidon.com",
  "mailblocks.com", "mailbucket.org", "mailcat.biz", "mailfreeonline.com",
  "mailguard.me", "mailhz.me", "mailin8r.com", "mailinator.com",
  "mailinator.email", "mailinator.royalapparelsrc.com", "mailinater.com",
  "mailismagic.com", "mailita.tk", "mailmate.com", "mailme.ir",
  "mailme.lv", "mailmetrash.com", "mailnator.com", "mailnext.com",
  "mailpick.biz", "mailrock.biz", "mailseal.de", "mailshiv.com",
  "mailsiphon.com", "mailslapping.com", "mailtemp.org", "meltmail.com",
  "mezimages.net", "ministry-of-silly-walks.de", "mintemail.com",
  "mohmal.com", "msa.minsmail.com", "mt2015.com", "mycard.net.ua",
  "mycleaninbox.net", "myspaceinc.com", "myspacepimpedup.com",
  "mytempemail.com", "mytrashmail.com", "nabala.com", "neomailbox.com",
  "nepwk.com", "nervmich.net", "nervtansen.de", "netmails.com",
  "netmails.net", "neverbox.com", "no-spam.ws", "noblepioneer.com",
  "nogmailspam.info", "nomail.pw", "nomail.xl.cx", "nomail2me.com",
  "nospam.ze.tc", "nothingtoseehere.ca", "nowmymail.com", "nurfuerspam.de",
  "nus.edu.sg", "objectmail.com", "obobbo.com", "oneoffemail.com",
  "onewaymail.com", "oopi.org", "ordinaryamerican.net", "owlpic.com",
  "pjjkp.com", "plexolan.de", "pookmail.com", "proxymail.eu",
  "putthisinyouremail.com", "qq.com", "quickinbox.com",
  "rcpt.at", "recode.me", "rejectmail.com", "rhyta.com",
  "rklips.com", "rmqkr.net", "royal.net", "rppkn.com",
  "rtrtr.com", "s0ny.net", "safe-mail.net", "safersignup.de",
  "safetymail.info", "safetypost.de", "sandelf.de",
  "saynotospams.com", "scatmail.com", "schafmail.de", "selfdestructingmail.com",
  "sharklasers.com", "shieldemail.com", "shiftmail.com",
  "skeefmail.com", "slaskpost.se", "slipry.net", "slopsbox.com",
  "smashmail.de", "soodonims.com", "spam4.me", "spamavert.com",
  "spambob.com", "spambob.net", "spambob.org", "spambog.com",
  "spambog.de", "spambog.ru", "spambox.us", "spamcannon.com",
  "spamcannon.net", "spamcero.com", "spamcorptastic.com", "spamcowboy.com",
  "spamcowboy.net", "spamcowboy.org", "spamday.com", "spamex.com",
  "spamfighter.cf", "spamfighter.ga", "spamfighter.gq", "spamfighter.ml",
  "spamfighter.tk", "spamfree24.com", "spamfree24.de", "spamfree24.eu",
  "spamfree24.info", "spamfree24.net", "spamfree24.org", "spamgourmet.com",
  "spamgourmet.net", "spamgourmet.org", "spamherelots.com",
  "spamhereplease.com", "spamhole.com", "spamify.com", "spaminator.de",
  "spamkill.info", "spaml.com", "spaml.de", "spammotel.com",
  "spamobox.com", "spamoff.de", "spamslicer.com", "spamspot.com",
  "spamstack.net", "spamthis.co.uk", "spamtrail.com", "spamtrap.ro",
  "speed.1s.fr", "superrito.com", "suremail.info",
  "teleworm.us", "tempail.com", "tempalias.com", "tempe4mail.com",
  "tempemail.co.za", "tempemail.net", "tempinbox.com",
  "tempmail.eu", "tempmail.it", "tempmail2.com", "tempmaildemo.com",
  "tempmailer.com", "tempmailer.de", "tempomail.fr",
  "temporaryemail.net", "temporaryemail.us", "temporaryforwarding.com",
  "temporaryinbox.com", "temporarymailaddress.com", "thankyou2010.com",
  "thisisnotmyrealemail.com", "throwam.com",
  "tmail.ws", "tmailinator.com", "toiea.com",
  "trashdevil.com", "trashdevil.de", "trashmail.de",
  "trashmail.ws", "trashmailer.com", "trashy.com",
  "trickmail.net", "trillianpro.com", "turual.com", "twinmail.de",
  "tyldd.com", "uggsrock.com", "umail.net", "upliftnow.com",
  "uplipht.com", "venompen.com", "veryreallycheap.org", "vomoto.com",
  "vpn.st", "vsimcard.com", "vubby.com", "wasteland.rfc822.org",
  "webemail.me", "weg-werfen.de", "wegwerfadresse.de", "wegwerfemail.com",
  "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
  "wh4f.org", "whatiaas.com", "whatpaas.com", "whyspam.me",
  "willhackforfood.biz", "willselfdestruct.com", "winemaven.info",
  "wronghead.com", "wuzup.net", "wuzupmail.net", "wwwnew.eu",
  "xagloo.com", "xemaps.com", "xents.com", "xjoi.com",
  "xmaily.com", "xoxy.net", "yep.it", "yogamaven.com",
  "yopmail.com", "yopmail.fr", "yuurok.com", "zehnminutenmail.de",
  "zippymail.info", "zoaxe.com", "zoemail.org",
]);

export function isDisposable(domain: string): boolean {
  return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

// ---------------------------------------------------------------------------
// DNS Helpers
// ---------------------------------------------------------------------------

async function resolveWithTimeout<T>(fn: () => Promise<T>): Promise<T> {
  return Promise.race([
    fn(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("DNS timeout")), DNS_TIMEOUT_MS)
    ),
  ]);
}

// ---------------------------------------------------------------------------
// MX Check
// ---------------------------------------------------------------------------

async function checkMx(domain: string): Promise<{
  found: boolean;
  records: { priority: number; hostname: string }[];
  acceptsMail: boolean;
}> {
  try {
    const records = await resolveWithTimeout(() => resolver.resolveMx(domain));
    if (!records || records.length === 0) {
      return { found: false, records: [], acceptsMail: false };
    }
    const sorted = records.sort((a, b) => a.priority - b.priority);
    return {
      found: true,
      records: sorted.map((r) => ({ priority: r.priority, hostname: r.exchange })),
      acceptsMail: true,
    };
  } catch {
    return { found: false, records: [], acceptsMail: false };
  }
}

// ---------------------------------------------------------------------------
// Deliverability Assessment
// ---------------------------------------------------------------------------

function assessDeliverability(
  syntaxValid: boolean,
  mxFound: boolean,
  disposable: boolean,
): "likely" | "unlikely" | "unknown" {
  if (!syntaxValid) return "unlikely";
  if (!mxFound) return "unlikely";
  if (disposable) return "unknown"; // disposable domains accept mail but addresses are ephemeral
  return "likely";
}

// ---------------------------------------------------------------------------
// Input Validation
// ---------------------------------------------------------------------------

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function validateEmail(input: string): { valid: boolean; email?: string; error?: string } {
  if (!input || typeof input !== "string") {
    return { valid: false, error: "Email parameter is required" };
  }
  const email = input.trim().toLowerCase();
  if (email.length > 254) {
    return { valid: false, error: "Email exceeds maximum length (254 chars)" };
  }
  if (!email.includes("@")) {
    return { valid: false, error: "Email must contain @" };
  }
  return { valid: true, email };
}

// ---------------------------------------------------------------------------
// Full Check (Paid)
// ---------------------------------------------------------------------------

export async function fullCheck(email: string): Promise<EmailVerifyResult> {
  const syntax = validateSyntax(email);
  const domain = syntax.domain;

  const mx = syntax.valid ? await checkMx(domain) : { found: false, records: [], acceptsMail: false };
  const disposable = syntax.valid ? isDisposable(domain) : false;
  const roleAddress = syntax.valid ? isRoleAddress(syntax.local) : false;
  const freeProvider = syntax.valid ? isFreeProvider(domain) : false;

  return {
    email,
    domain: domain || email.split("@")[1] || "",
    syntax: { valid: syntax.valid, local: syntax.local, domain: syntax.domain },
    mx,
    disposable,
    roleAddress,
    freeProvider,
    deliverable: assessDeliverability(syntax.valid, mx.found, disposable),
    checkedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Preview Check (Free — syntax + disposable + role only, no DNS)
// ---------------------------------------------------------------------------

export async function previewCheck(email: string): Promise<EmailVerifyPreview> {
  const syntax = validateSyntax(email);
  const domain = syntax.domain;

  return {
    email,
    domain: domain || email.split("@")[1] || "",
    syntax: { valid: syntax.valid },
    disposable: syntax.valid ? isDisposable(domain) : false,
    roleAddress: syntax.valid ? isRoleAddress(syntax.local) : false,
    freeProvider: syntax.valid ? isFreeProvider(domain) : false,
    checkedAt: new Date().toISOString(),
  };
}
