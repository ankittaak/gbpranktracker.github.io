import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const MAX_BATCH_PAGES = 10;
const MAX_PAGE_LIMIT = 100;
const MAX_SITEMAP_PAGES = 100;
const PAGE_BATCH_SIZE = 3;
const MAX_PAGE_BYTES = 900000;
const MAX_AUX_BYTES = 300000;
const FETCH_TIMEOUT_MS = 5000;
const USER_AGENT = "TrexivoSEOAuditBot/1.0";

const rateLimits = new Map();

function normalizeHostname(hostname) {
  return hostname.toLowerCase().replace(/^www\./, "");
}

function isPrivateAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const parts = address.split(".").map(Number);
    const a = parts[0];
    const b = parts[1];
    const c = parts[2];
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113);
  }

  if (family === 6) {
    const value = address.toLowerCase();
    return value === "::" || value === "::1"
      || value.startsWith("fc") || value.startsWith("fd")
      || /^fe[89ab]/.test(value)
      || value.startsWith("ff")
      || value.startsWith("2001:db8")
      || value.startsWith("::ffff:");
  }

  return true;
}

async function ensurePublicHost(hostname) {
  if (!hostname || isIP(hostname) || !hostname.includes(".")
      || hostname.endsWith(".localhost") || hostname.endsWith(".local")
      || hostname.endsWith(".internal") || hostname.endsWith(".test")
      || hostname.endsWith(".invalid")) {
    throw new Error("Enter a public website domain.");
  }

  let records;
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("The website domain could not be reached.");
  }

  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("This audit only accepts websites hosted on public addresses.");
  }
}

function normalizeInputUrl(value, preservePath = false) {
  let input = String(value || "").trim();
  if (!input) throw new Error("Enter a website address.");
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;

  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error("Enter a valid website address.");
  }

  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Use a public website address starting with http:// or https://.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("Custom ports are not supported.");
  }

  if (!preservePath) {
    url.pathname = "/";
    url.search = "";
  }
  url.hash = "";
  return url;
}

function hostIsInScope(hostname, rootHostname) {
  return normalizeHostname(hostname) === normalizeHostname(rootHostname);
}

async function readLimitedText(response, maxBytes) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("The page is larger than the audit size limit.");
    }
    chunks.push(part.value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(merged);
}

async function fetchWebsiteText(value, rootHostname, maxBytes) {
  let current = new URL(value);
  const startedAt = Date.now();

  for (let redirectCount = 0; redirectCount <= 3; redirectCount += 1) {
    if (!["http:", "https:"].includes(current.protocol)
        || !hostIsInScope(current.hostname, rootHostname)
        || (current.port && !["80", "443"].includes(current.port))) {
      return {
        url: current.toString(),
        finalUrl: current.toString(),
        status: 0,
        headers: new Headers(),
        text: "",
        outOfScopeRedirect: true,
        durationMs: Date.now() - startedAt
      };
    }

    await ensurePublicHost(current.hostname);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const response = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/xml,text/xml,text/plain,*/*;q=0.5"
        },
        signal: controller.signal
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) {
          return {
            url: value,
            finalUrl: current.toString(),
            status: response.status,
            headers: response.headers,
            text: "",
            durationMs: Date.now() - startedAt
          };
        }
        const next = new URL(location, current);
        if (!hostIsInScope(next.hostname, rootHostname)) {
          return {
            url: value,
            finalUrl: next.toString(),
            status: response.status,
            headers: response.headers,
            text: "",
            outOfScopeRedirect: true,
            durationMs: Date.now() - startedAt
          };
        }
        current = next;
        continue;
      }

      const text = await readLimitedText(response, maxBytes);
      return {
        url: value,
        finalUrl: current.toString(),
        status: response.status,
        headers: response.headers,
        text,
        contentType: response.headers.get("content-type") || "",
        durationMs: Date.now() - startedAt
      };
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error("The website redirected too many times.");
}

function decodeCodePoint(match, value, radix) {
  const codePoint = parseInt(value, radix);
  if (!Number.isFinite(codePoint) || codePoint < 0 || codePoint > 0x10ffff
      || (codePoint >= 0xd800 && codePoint <= 0xdfff)) return match;
  return String.fromCodePoint(codePoint);
}

function decodeEntities(value) {
  return String(value || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (match, code) => decodeCodePoint(match, code, 10))
    .replace(/&#x([0-9a-f]+);/gi, (match, code) => decodeCodePoint(match, code, 16));
}

function getAttribute(tag, name) {
  let index = tag.indexOf("<") + 1;
  while (index < tag.length && ![32, 9, 10, 13, 12].includes(tag.charCodeAt(index)) && tag[index] !== ">") index += 1;

  while (index < tag.length) {
    while ([32, 9, 10, 13, 12].includes(tag.charCodeAt(index))) index += 1;
    if (index >= tag.length || tag[index] === ">" || tag[index] === "/") break;

    const keyStart = index;
    while (index < tag.length && ![32, 9, 10, 13, 12].includes(tag.charCodeAt(index))
        && tag[index] !== "=" && tag[index] !== ">" && tag[index] !== "/") index += 1;
    const key = tag.slice(keyStart, index).toLowerCase();

    while ([32, 9, 10, 13, 12].includes(tag.charCodeAt(index))) index += 1;
    if (tag[index] !== "=") continue;
    index += 1;
    while ([32, 9, 10, 13, 12].includes(tag.charCodeAt(index))) index += 1;

    let value = "";
    const quote = tag[index] === "'" || tag[index] === "\"" ? tag[index] : "";
    if (quote) {
      index += 1;
      const valueStart = index;
      while (index < tag.length && tag[index] !== quote) index += 1;
      value = tag.slice(valueStart, index);
      if (tag[index] === quote) index += 1;
    } else {
      const valueStart = index;
      while (index < tag.length && ![32, 9, 10, 13, 12].includes(tag.charCodeAt(index))
          && tag[index] !== ">") index += 1;
      value = tag.slice(valueStart, index);
    }

    if (key === name.toLowerCase()) return decodeEntities(value);
  }

  return null;
}

function stripHtml(value) {
  return decodeEntities(String(value || "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

function getMetaContent(html, metaName) {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const name = getAttribute(tag, "name");
    if (name && name.toLowerCase() === metaName.toLowerCase()) {
      return getAttribute(tag, "content") || "";
    }
  }
  return "";
}

function getMetaPropertyContent(html, propertyName) {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const property = getAttribute(tag, "property");
    if (property && property.toLowerCase() === propertyName.toLowerCase()) {
      return getAttribute(tag, "content") || "";
    }
  }
  return "";
}

function getStructuredData(html) {
  const types = new Set();
  let blocks = 0;
  let invalidBlocks = 0;
  const scripts = html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi);

  for (const script of scripts) {
    const openingTag = "<script" + script[1] + ">";
    const type = getAttribute(openingTag, "type") || "";
    if (type.toLowerCase().split(";")[0].trim() !== "application/ld+json") continue;
    blocks += 1;

    let parsed;
    try {
      parsed = JSON.parse(script[2].trim());
    } catch {
      invalidBlocks += 1;
      continue;
    }

    const pending = [parsed];
    let visited = 0;
    while (pending.length && visited < 500) {
      const value = pending.pop();
      visited += 1;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (pending.length < 500) pending.push(item);
        }
      } else if (value && typeof value === "object") {
        const itemTypes = value["@type"];
        if (Array.isArray(itemTypes)) itemTypes.forEach((item) => types.add(String(item)));
        else if (itemTypes) types.add(String(itemTypes));
        for (const item of Object.values(value)) {
          if (item && typeof item === "object" && pending.length < 500) pending.push(item);
        }
      }
    }
  }

  return { blocks, invalidBlocks, types: Array.from(types).slice(0, 12) };
}

function getRobotsRules(text) {
  const groups = [];
  const sitemapUrls = [];
  let agents = [];
  let rules = [];
  let groupHasRules = false;

  const flush = () => {
    if (agents.length) groups.push({ agents: agents.slice(), rules: rules.slice() });
    agents = [];
    rules = [];
    groupHasRules = false;
  };

  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    if (!line) continue;

    const sitemapMatch = line.match(/^sitemap\s*:\s*(\S+)/i);
    if (sitemapMatch) {
      sitemapUrls.push(sitemapMatch[1]);
      continue;
    }

    const agentMatch = line.match(/^user-agent\s*:\s*(.+)$/i);
    if (agentMatch) {
      if (groupHasRules) flush();
      agents.push(agentMatch[1].trim().toLowerCase());
      continue;
    }

    const ruleMatch = line.match(/^(allow|disallow)\s*:\s*(.*)$/i);
    if (ruleMatch && agents.length) {
      const path = ruleMatch[2].trim();
      if (path) {
        rules.push({ allow: ruleMatch[1].toLowerCase() === "allow", path });
        groupHasRules = true;
      }
    }
  }
  flush();

  const exactGroups = groups.filter((group) => group.agents.includes("trexivoseoauditbot"));
  const starGroups = groups.filter((group) => group.agents.includes("*"));
  const selected = exactGroups.length ? exactGroups : starGroups;

  return {
    rules: selected.flatMap((group) => group.rules),
    sitemapUrls: Array.from(new Set(sitemapUrls)).slice(0, 3)
  };
}

function isAllowedByRobots(path, rules) {
  let best = null;

  for (const rule of rules) {
    const endAnchored = rule.path.endsWith("$");
    const rawPattern = endAnchored ? rule.path.slice(0, -1) : rule.path;
    const wildcardPrefix = rawPattern.split("*")[0];
    const matches = rule.path.includes("*")
      ? path.startsWith(wildcardPrefix)
      : endAnchored ? path === rawPattern : path.startsWith(rawPattern);
    if (!matches) continue;

    const specificity = rawPattern.replaceAll("*", "").length;
    if (!best || specificity > best.specificity
        || (specificity === best.specificity && rule.allow)) {
      best = { specificity, allow: rule.allow };
    }
  }

  return !best || best.allow;
}

function cleanCandidateUrl(value, baseUrl, rootHostname) {
  try {
    const url = new URL(value, baseUrl);
    if (!["http:", "https:"].includes(url.protocol)
        || !hostIsInScope(url.hostname, rootHostname)
        || (url.port && !["80", "443"].includes(url.port))) return null;

    url.hash = "";
    url.search = "";
    if (/\.(?:jpg|jpeg|png|gif|webp|svg|pdf|zip|css|js|woff2?|ttf|ico|mp4|mp3)$/i.test(url.pathname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function findPageLinks(html, baseUrl, rootHostname) {
  const links = new Set();
  const tags = html.match(/<a\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const href = getAttribute(tag, "href");
    if (!href) continue;
    const candidate = cleanCandidateUrl(href, baseUrl, rootHostname);
    if (candidate) links.add(candidate);
  }
  return Array.from(links);
}

function findSitemapLocations(text) {
  return Array.from(String(text || "").matchAll(/<loc\b[^>]*>\s*([\s\S]*?)\s*<\/loc>/gi))
    .map((match) => stripHtml(match[1]))
    .filter(Boolean);
}

function addIssue(issues, severity, code, title, recommendation) {
  issues.push({ severity, code, title, recommendation });
}

function addDuplicateFieldIssues(pages, field, code, title, recommendation) {
  const groups = new Map();
  for (const page of pages) {
    const value = String(page[field] || "").trim().toLowerCase().replace(/\s+/g, " ");
    if (!value) continue;
    if (!groups.has(value)) groups.set(value, []);
    groups.get(value).push(page);
  }

  for (const group of groups.values()) {
    if (group.length < 2) continue;
    for (const page of group) {
      addIssue(page.issues, "warning", code, title,
        recommendation + " Duplicate found on " + group.length + " scanned pages.");
    }
  }
}

function addBrokenInternalLinkIssues(pages) {
  const statusByUrl = new Map();
  for (const page of pages) {
    if (page.url) statusByUrl.set(page.url, page.status);
    if (page.finalUrl) statusByUrl.set(page.finalUrl, page.status);
  }

  for (const page of pages) {
    const brokenLinks = Array.from(new Set((page.links || []).filter((link) => {
      const status = statusByUrl.get(link);
      return Number(status) >= 400;
    })));
    page.brokenInternalLinks = brokenLinks.length;
    if (brokenLinks.length) addIssue(page.issues, "warning", "broken-internal-links",
      brokenLinks.length + " internal link(s) point to scanned pages that return an error",
      "Update or remove links to the affected pages. This check only covers links whose targets were scanned.");
  }
}

function auditPage(url, response, rootHostname) {
  const html = response.text || "";
  const issues = [];
  const status = response.status || null;

  if (response.outOfScopeRedirect) {
    addIssue(issues, "warning", "external-redirect", "Redirects outside this website",
      "Enter the final website address so the audit stays within one site.");
    return { url, finalUrl: response.finalUrl, status, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, responseTimeMs: response.durationMs || null, issues, links: [] };
  }

  if (!status) {
    addIssue(issues, "critical", "fetch-failed", "Page could not be fetched",
      "Check that the page is public and responds to a normal browser request.");
    return { url, finalUrl: response.finalUrl || url, status: null, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, responseTimeMs: response.durationMs || null, issues, links: [] };
  }

  if (status >= 400) {
    addIssue(issues, status >= 500 ? "critical" : "warning", "http-status", "Page returned HTTP " + status,
      "Fix the URL or restore the page if it should be available.");
  }

  const isHtml = /html|xhtml/i.test(response.contentType || "")
    || /<html\b|<head\b|<title\b/i.test(html);
  if (!isHtml && status < 400) {
    addIssue(issues, "info", "not-html", "URL is not an HTML page",
      "This first audit checks HTML pages; non-HTML files are listed but not analyzed.");
    return { url, finalUrl: response.finalUrl, status, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, responseTimeMs: response.durationMs || null, issues, links: [] };
  }

  const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? stripHtml(titleMatch[1]) : "";
  const description = getMetaContent(html, "description").trim();
  const htmlTag = html.match(/<html\b[^>]*>/i);
  const language = htmlTag ? getAttribute(htmlTag[0], "lang") || "" : "";
  const h1Tags = html.match(/<h1\b[^>]*>[\s\S]*?<\/h1>/gi) || [];
  const h2Tags = html.match(/<h2\b[^>]*>[\s\S]*?<\/h2>/gi) || [];
  const headingLevels = Array.from(html.matchAll(/<h([1-6])\b[^>]*>/gi), (match) => Number(match[1]));
  const skipsHeadingLevel = headingLevels.some((level, index) => index > 0 && level > headingLevels[index - 1] + 1);
  const canonicalTag = (html.match(/<link\b[^>]*>/gi) || []).find((tag) => {
    const rel = getAttribute(tag, "rel") || "";
    return rel.toLowerCase().split(/\s+/).includes("canonical");
  });
  const canonical = canonicalTag ? getAttribute(canonicalTag, "href") || "" : "";
  let canonicalIsExternal = false;
  if (canonical) {
    try {
      canonicalIsExternal = !hostIsInScope(new URL(canonical, response.finalUrl || url).hostname, rootHostname);
    } catch {
      canonicalIsExternal = true;
    }
  }
  const robotsMeta = (getMetaContent(html, "robots") + " " + getMetaContent(html, "googlebot")).toLowerCase();
  const noindex = /noindex/i.test(robotsMeta) || /noindex/i.test(response.headers.get("x-robots-tag") || "");
  const imageTags = html.match(/<img\b[^>]*>/gi) || [];
  const missingAltCount = imageTags.filter((tag) => {
    const alt = getAttribute(tag, "alt");
    return alt === null || !alt.trim();
  }).length;
  const hasViewport = (html.match(/<meta\b[^>]*>/gi) || []).some((tag) => {
    return (getAttribute(tag, "name") || "").toLowerCase() === "viewport";
  });
  const ogTitle = getMetaPropertyContent(html, "og:title").trim();
  const ogDescription = getMetaPropertyContent(html, "og:description").trim();
  const structuredData = getStructuredData(html);
  const links = findPageLinks(html, response.finalUrl || url, rootHostname);
  const externalLinks = (html.match(/<a\b[^>]*>/gi) || []).filter((tag) => {
    const href = getAttribute(tag, "href");
    if (!href) return false;
    try {
      const target = new URL(href, response.finalUrl || url);
      return ["http:", "https:"].includes(target.protocol) && !hostIsInScope(target.hostname, rootHostname);
    } catch {
      return false;
    }
  }).length;

  if (!title) addIssue(issues, "warning", "missing-title", "Missing page title",
    "Add a concise, unique title that describes this page.");
  else if (title.length < 30 || title.length > 60) addIssue(issues, "info", "title-length", "Title length is outside the suggested range",
    "Review the title for clarity; this character range is a guideline, not a Google ranking rule.");

  if (!description) addIssue(issues, "warning", "missing-description", "Missing meta description",
    "Add a clear summary of the page. Google may choose a different search snippet.");
  else if (description.length < 70 || description.length > 160) addIssue(issues, "info", "description-length", "Description length is outside the suggested range",
    "Review the summary for clarity; snippet length can vary in Google Search.");

  if (!h1Tags.length) addIssue(issues, "warning", "missing-h1", "No H1 heading found",
    "Add a clear main heading that describes the page content.");
  else if (h1Tags.length > 1) addIssue(issues, "info", "multiple-h1", "More than one H1 heading found",
    "Check that the page has a clear primary heading and a useful heading structure.");
  if (skipsHeadingLevel) addIssue(issues, "warning", "heading-order", "Heading levels skip a level",
    "Keep heading levels in a logical order so readers and assistive technology can follow the page structure.");

  if (!canonical) addIssue(issues, "info", "missing-canonical", "No canonical link found",
    "Add a canonical link if this page has duplicate or alternate URLs.");
  else if (canonicalIsExternal) addIssue(issues, "warning", "external-canonical", "Canonical points to a different website",
    "Check that the canonical URL is intentional and points to the preferred version of this page.");
  if (noindex) addIssue(issues, "critical", "noindex", "Page is marked noindex",
    "Remove the noindex directive if this page should appear in search results.");
  if (!language) addIssue(issues, "info", "missing-language", "Page language is not declared",
    "Set the correct lang attribute on the html element to help browsers and assistive technology identify the page language.");
  if (!hasViewport) addIssue(issues, "warning", "missing-viewport", "Missing mobile viewport setting",
    "Add a viewport meta tag so the page scales correctly on mobile devices.");
  if (missingAltCount) addIssue(issues, "warning", "missing-image-alt", missingAltCount + " image(s) have no alt text",
    "Add useful alternative text to informative images; use empty alt text for decorative images.");
  if (!ogTitle || !ogDescription) addIssue(issues, "info", "open-graph", "Open Graph sharing tags are incomplete",
    "Add og:title and og:description so shared links have a clear preview on social platforms.");
  if (!structuredData.blocks) addIssue(issues, "info", "missing-structured-data", "No JSON-LD structured data found",
    "Consider adding valid structured data for content types that support it, such as local businesses, products, or articles.");
  if (structuredData.invalidBlocks) addIssue(issues, "warning", "invalid-structured-data", "Some JSON-LD blocks are not valid JSON",
    "Fix the JSON syntax in each application/ld+json script block.");

  return {
    url,
    finalUrl: response.finalUrl || url,
    status,
    title,
    titleLength: title.length,
    description,
    descriptionLength: description.length,
    language,
    h1Count: h1Tags.length,
    h2Count: h2Tags.length,
    canonical,
    canonicalIsExternal,
    noindex,
    ogTitle,
    ogDescription,
    structuredDataCount: structuredData.blocks,
    structuredDataInvalidCount: structuredData.invalidBlocks,
    structuredDataTypes: structuredData.types,
    imageCount: imageTags.length,
    missingAltCount,
    internalLinks: links.length,
    externalLinks,
    responseTimeMs: response.durationMs || null,
    issues,
    links
  };
}

function rateLimitKey(request) {
  const forwarded = request.headers.get("x-forwarded-for") || "";
  return forwarded.split(",")[0].trim() || "unknown";
}

function allowAuditRequest(request) {
  const now = Date.now();
  const key = rateLimitKey(request);
  const current = rateLimits.get(key);
  if (!current || current.resetAt <= now) {
    rateLimits.set(key, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (current.count >= 20) return false;
  current.count += 1;
  return true;
}

async function getSitemapPages(siteUrl, rootHostname, robotsSitemaps, robotsRules) {
  const firstSitemaps = robotsSitemaps.length
    ? robotsSitemaps
    : [new URL("/sitemap.xml", siteUrl).toString()];
  const sitemapQueue = firstSitemaps.slice(0, 3);
  const visitedSitemaps = new Set();
  const pages = [];
  let firstStatus = null;

  while (sitemapQueue.length && visitedSitemaps.size < 5 && pages.length < MAX_SITEMAP_PAGES) {
    const sitemapUrl = sitemapQueue.shift();
    if (!sitemapUrl || visitedSitemaps.has(sitemapUrl)) continue;
    visitedSitemaps.add(sitemapUrl);

    try {
      const response = await fetchWebsiteText(sitemapUrl, rootHostname, MAX_AUX_BYTES);
      if (firstStatus === null) firstStatus = response.status || null;
      if (response.status < 200 || response.status >= 300) continue;
      const locations = findSitemapLocations(response.text);
      if (/<sitemapindex\b/i.test(response.text)) {
        for (const location of locations.slice(0, 6)) {
          const childSitemap = cleanCandidateUrl(location, siteUrl, rootHostname);
          if (childSitemap && !visitedSitemaps.has(childSitemap)) sitemapQueue.push(childSitemap);
        }
      } else {
        for (const location of locations) {
          const pageUrl = cleanCandidateUrl(location, siteUrl, rootHostname);
          if (pageUrl && isAllowedByRobots(new URL(pageUrl).pathname, robotsRules)) pages.push(pageUrl);
           if (pages.length >= MAX_SITEMAP_PAGES) break;
        }
      }
    } catch {
      // A missing or unreadable sitemap does not prevent checking the homepage.
    }
  }

  return {
    pages: Array.from(new Set(pages)).slice(0, MAX_SITEMAP_PAGES),
    status: firstStatus,
    sitemapsChecked: visitedSitemaps.size
  };
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return Response.json({ error: "Use POST for audits." }, { status: 405 });
    }
    if (!allowAuditRequest(request)) {
      return Response.json({ error: "Please wait a minute before starting another audit." }, { status: 429 });
    }

    try {
      const input = await request.json();
      const mode = input.mode === "single" ? "single" : "bulk";
      const selectedPageLimit = Number(input.pageLimit);
      const requestedPageLimit = mode === "single" ? 1
        : selectedPageLimit <= MAX_PAGE_LIMIT && [10, 20, 50, 100].includes(selectedPageLimit) ? selectedPageLimit : 10;
      const startUrl = normalizeInputUrl(input.url, mode === "single");
      const rootHostname = startUrl.hostname;
      await ensurePublicHost(rootHostname);

      const robotsUrl = new URL("/robots.txt", startUrl).toString();
      let robotsResponse;
      try {
        robotsResponse = await fetchWebsiteText(robotsUrl, rootHostname, MAX_AUX_BYTES);
      } catch {
        return Response.json(
          { error: "Could not read this website's robots.txt, so the audit stopped safely." },
          { status: 502 }
        );
      }

      if (robotsResponse.outOfScopeRedirect) {
        return Response.json(
          { error: "This website redirects robots.txt to a different domain, so the audit stopped safely." },
          { status: 502 }
        );
      }

      if (robotsResponse.status === 403 || robotsResponse.status === 429 || robotsResponse.status >= 500) {
        return Response.json(
          { error: "The website did not allow the audit to read robots.txt." },
          { status: 502 }
        );
      }

      const robots = getRobotsRules(robotsResponse.text);
      const siteUrl = new URL("/", robotsResponse.finalUrl || startUrl.toString()).toString();

      const discoverSitemap = mode === "single" || input.discoverSitemap === true;
      const sitemapResult = discoverSitemap
        ? await getSitemapPages(siteUrl, rootHostname, robots.sitemapUrls, robots.rules)
        : { pages: [], status: null, sitemapsChecked: 0 };
      const requestedUrls = Array.isArray(input.pageUrls) ? input.pageUrls : [mode === "single" ? startUrl.toString() : siteUrl];
      const queue = [];
      for (const value of requestedUrls.slice(0, MAX_BATCH_PAGES)) {
        const candidate = mode === "single" ? startUrl.toString() : cleanCandidateUrl(value, siteUrl, rootHostname);
        if (candidate && !queue.includes(candidate)) queue.push(candidate);
      }
      if (mode === "bulk" && discoverSitemap) {
        for (const sitemapPage of sitemapResult.pages) {
          if (!queue.includes(sitemapPage) && queue.length < 500) queue.push(sitemapPage);
        }
      }
      const excludedUrls = Array.isArray(input.excludeUrls) ? input.excludeUrls : [];
      const visited = new Set(excludedUrls.slice(0, 2000)
        .map((value) => cleanCandidateUrl(value, siteUrl, rootHostname))
        .filter(Boolean));
      const pages = [];
      const discoveredLinks = new Set(sitemapResult.pages);
      let skippedByRobots = 0;
      const requestedBatchLimit = Number(input.batchLimit);
      const batchPageLimit = mode === "single" ? 1
        : requestedBatchLimit >= 1 && requestedBatchLimit <= MAX_BATCH_PAGES
          ? Math.min(requestedBatchLimit, requestedPageLimit)
          : Math.min(MAX_BATCH_PAGES, requestedPageLimit);

      while (queue.length && pages.length < batchPageLimit) {
        const batch = [];
        while (queue.length && batch.length < PAGE_BATCH_SIZE && pages.length + batch.length < batchPageLimit) {
          const candidate = queue.shift();
          if (!candidate || visited.has(candidate)) continue;
          visited.add(candidate);
          if (!isAllowedByRobots(new URL(candidate).pathname, robots.rules)) {
            skippedByRobots += 1;
            continue;
          }
          batch.push(candidate);
        }
        if (!batch.length) continue;

        const batchResults = await Promise.all(batch.map(async (pageUrl) => {
          try {
            const response = await fetchWebsiteText(pageUrl, rootHostname, MAX_PAGE_BYTES);
            return auditPage(pageUrl, response, rootHostname);
          } catch (error) {
            return auditPage(pageUrl, {
              status: null,
              finalUrl: pageUrl,
              text: "",
              headers: new Headers(),
              contentType: "",
              error: error && error.message ? error.message : "Page could not be fetched."
            }, rootHostname);
          }
        }));

        for (const page of batchResults) {
          pages.push(page);
          for (const link of page.links || []) {
            discoveredLinks.add(link);
            if (!visited.has(link) && queue.length < 100) queue.push(link);
          }
        }
      }

      addDuplicateFieldIssues(pages, "title", "duplicate-title", "Duplicate page title",
        "Give each page a distinct title that describes its own content.");
      addDuplicateFieldIssues(pages, "description", "duplicate-description", "Duplicate meta description",
        "Write a unique summary for each page.");
      addBrokenInternalLinkIssues(pages);

      const robotsStatus = robotsResponse.status || null;
      const sitemapStatus = sitemapResult.status;
      const siteChecks = [
        {
          code: "https",
          label: "HTTPS",
          status: new URL(siteUrl).protocol === "https:" ? "good" : "warning",
          detail: new URL(siteUrl).protocol === "https:" ? "The audited site uses HTTPS." : "The audited site is served over HTTP."
        },
        {
          code: "robots",
          label: "robots.txt",
          status: robotsStatus >= 200 && robotsStatus < 300 ? "good" : robotsStatus === 404 ? "info" : "warning",
          detail: robotsStatus >= 200 && robotsStatus < 300
            ? robots.rules.length + " crawl rule(s) read."
            : robotsStatus === 404 ? "No robots.txt file was found." : "Could not confirm robots.txt availability (HTTP " + (robotsStatus || "unknown") + ")."
        },
        {
          code: "sitemap",
          label: "XML sitemap",
          status: sitemapStatus >= 200 && sitemapStatus < 300 ? "good" : sitemapStatus === 404 ? "info" : "warning",
          detail: sitemapStatus >= 200 && sitemapStatus < 300
            ? sitemapResult.pages.length + " allowed page URL(s) found in " + sitemapResult.sitemapsChecked + " sitemap(s)."
            : sitemapStatus === 404 ? "No sitemap was found at the discovered location." : "Could not confirm a sitemap (HTTP " + (sitemapStatus || "unknown") + ")."
        }
      ];

      const counts = { critical: 0, warning: 0, info: 0 };
      for (const page of pages) {
        for (const issue of page.issues) counts[issue.severity] += 1;
      }
      for (const check of siteChecks) {
        if (check.status === "warning") counts.warning += 1;
        else if (check.status === "info") counts.info += 1;
      }

      return Response.json({
        site: siteUrl,
        mode,
        pagesScanned: pages.length,
        pageLimit: requestedPageLimit,
        batchPageLimit,
        skippedByRobots,
        discoveredLinks: Array.from(discoveredLinks).slice(0, 500),
        siteChecks,
        crawlability: {
          robotsStatus,
          robotsRules: robots.rules.length,
          sitemapStatus,
          sitemapPagesFound: sitemapResult.pages.length,
          sitemapsChecked: sitemapResult.sitemapsChecked
        },
        summary: {
          critical: counts.critical,
          warnings: counts.warning,
          info: counts.info,
          totalIssues: counts.critical + counts.warning + counts.info,
          pagesWithIssues: pages.filter((page) => page.issues.length > 0).length
        },
        pages
      });
    } catch (error) {
      return Response.json(
        { error: error && error.message ? error.message : "The audit could not be completed." },
        { status: 400 }
      );
    }
  }
};

