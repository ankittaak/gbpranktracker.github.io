import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const MAX_PAGES = 10;
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

function normalizeInputUrl(value) {
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

  url.pathname = "/";
  url.search = "";
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
        outOfScopeRedirect: true
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
            text: ""
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
            outOfScopeRedirect: true
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
        contentType: response.headers.get("content-type") || ""
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

function auditPage(url, response, rootHostname) {
  const html = response.text || "";
  const issues = [];
  const status = response.status || null;

  if (response.outOfScopeRedirect) {
    addIssue(issues, "warning", "external-redirect", "Redirects outside this website",
      "Enter the final website address so the audit stays within one site.");
    return { url, finalUrl: response.finalUrl, status, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, issues, links: [] };
  }

  if (!status) {
    addIssue(issues, "critical", "fetch-failed", "Page could not be fetched",
      "Check that the page is public and responds to a normal browser request.");
    return { url, finalUrl: response.finalUrl || url, status: null, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, issues, links: [] };
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
    return { url, finalUrl: response.finalUrl, status, title: "", description: "", h1Count: 0, canonical: "", noindex: false, missingAltCount: 0, internalLinks: 0, issues, links: [] };
  }

  const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? stripHtml(titleMatch[1]) : "";
  const description = getMetaContent(html, "description").trim();
  const h1Tags = html.match(/<h1\b[^>]*>[\s\S]*?<\/h1>/gi) || [];
  const canonicalTag = (html.match(/<link\b[^>]*>/gi) || []).find((tag) => {
    const rel = getAttribute(tag, "rel") || "";
    return rel.toLowerCase().split(/\s+/).includes("canonical");
  });
  const canonical = canonicalTag ? getAttribute(canonicalTag, "href") || "" : "";
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
  const links = findPageLinks(html, response.finalUrl || url, rootHostname);

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

  if (!canonical) addIssue(issues, "info", "missing-canonical", "No canonical link found",
    "Add a canonical link if this page has duplicate or alternate URLs.");
  if (noindex) addIssue(issues, "critical", "noindex", "Page is marked noindex",
    "Remove the noindex directive if this page should appear in search results.");
  if (!hasViewport) addIssue(issues, "warning", "missing-viewport", "Missing mobile viewport setting",
    "Add a viewport meta tag so the page scales correctly on mobile devices.");
  if (missingAltCount) addIssue(issues, "warning", "missing-image-alt", missingAltCount + " image(s) have no alt text",
    "Add useful alternative text to informative images; use empty alt text for decorative images.");

  return {
    url,
    finalUrl: response.finalUrl || url,
    status,
    title,
    description,
    h1Count: h1Tags.length,
    canonical,
    noindex,
    missingAltCount,
    internalLinks: links.length,
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
  if (current.count >= 5) return false;
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

  while (sitemapQueue.length && visitedSitemaps.size < 3 && pages.length < 40) {
    const sitemapUrl = sitemapQueue.shift();
    if (!sitemapUrl || visitedSitemaps.has(sitemapUrl)) continue;
    visitedSitemaps.add(sitemapUrl);

    try {
      const response = await fetchWebsiteText(sitemapUrl, rootHostname, MAX_AUX_BYTES);
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
          if (pages.length >= 40) break;
        }
      }
    } catch {
      // A missing or unreadable sitemap does not prevent checking the homepage.
    }
  }

  return Array.from(new Set(pages)).slice(0, 40);
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
      const startUrl = normalizeInputUrl(input.url);
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

      const sitemapPages = await getSitemapPages(siteUrl, rootHostname, robots.sitemapUrls, robots.rules);
      const queue = [siteUrl, ...sitemapPages];
      const visited = new Set();
      const pages = [];
      let skippedByRobots = 0;

      while (queue.length && pages.length < MAX_PAGES) {
        const batch = [];
        while (queue.length && batch.length < PAGE_BATCH_SIZE && pages.length + batch.length < MAX_PAGES) {
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
            if (!visited.has(link) && queue.length < 100) queue.push(link);
          }
        }
      }

      const counts = { critical: 0, warning: 0, info: 0 };
      for (const page of pages) {
        for (const issue of page.issues) counts[issue.severity] += 1;
      }

      return Response.json({
        site: siteUrl,
        pagesScanned: pages.length,
        pageLimit: MAX_PAGES,
        skippedByRobots,
        summary: {
          critical: counts.critical,
          warnings: counts.warning,
          info: counts.info,
          totalIssues: counts.critical + counts.warning + counts.info,
          pagesWithIssues: pages.filter((page) => page.issues.length > 0).length
        },
        pages: pages.map(({ links, ...page }) => page)
      });
    } catch (error) {
      return Response.json(
        { error: error && error.message ? error.message : "The audit could not be completed." },
        { status: 400 }
      );
    }
  }
};
