import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const requestsByClient = new Map();
const PAGE_SPEED_TIMEOUT_MS = 45000;

function isPrivateAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 0 || b === 168))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113);
  }
  if (family === 6) {
    const value = address.toLowerCase();
    return value === "::" || value === "::1" || value.startsWith("fc")
      || value.startsWith("fd") || /^fe[89ab]/.test(value)
      || value.startsWith("ff") || value.startsWith("2001:db8")
      || value.startsWith("::ffff:");
  }
  return true;
}

async function ensurePublicHost(hostname) {
  if (!hostname || isIP(hostname) || !hostname.includes(".")
      || hostname.endsWith(".localhost") || hostname.endsWith(".local")
      || hostname.endsWith(".internal") || hostname.endsWith(".test")
      || hostname.endsWith(".invalid")) {
    throw new Error("Enter a public page URL.");
  }

  let records;
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("The page domain could not be reached.");
  }
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("PageSpeed only accepts public websites.");
  }
}

function normalizePageUrl(value) {
  let input = String(value || "").trim();
  if (!input) throw new Error("Enter a page URL.");
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error("Enter a valid page URL.");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Use a public page URL starting with http:// or https://.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new Error("Custom ports are not supported.");
  }
  url.hash = "";
  return url;
}

function allowRequest(request) {
  const now = Date.now();
  const key = (request.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
  const current = requestsByClient.get(key);
  if (!current || current.resetAt <= now) {
    requestsByClient.set(key, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (current.count >= 5) return false;
  current.count += 1;
  return true;
}

function cleanText(value) {
  return String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function scoreFor(category) {
  return Number.isFinite(category?.score) ? Math.round(category.score * 100) : null;
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return Response.json({ error: "Use POST for PageSpeed checks." }, { status: 405 });
    }
    if (!allowRequest(request)) {
      return Response.json({ error: "PageSpeed checks are limited. Please wait a minute and try again." }, { status: 429 });
    }

    try {
      const input = await request.json();
      const url = normalizePageUrl(input.url);
      await ensurePublicHost(url.hostname);
      const strategy = input.strategy === "desktop" ? "desktop" : "mobile";
      const query = new URLSearchParams({ url: url.toString(), strategy });
      for (const category of ["performance", "accessibility", "best-practices", "seo"]) {
        query.append("category", category);
      }
      const apiKey = typeof process !== "undefined" ? process.env.GOOGLE_PAGESPEED_API_KEY : "";
      if (apiKey) query.set("key", apiKey);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), PAGE_SPEED_TIMEOUT_MS);
      let response;
      try {
        response = await fetch("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?" + query.toString(), {
          signal: controller.signal,
          headers: { accept: "application/json" }
        });
      } finally {
        clearTimeout(timer);
      }

      if (!response.ok) {
        if (response.status === 429) {
          return Response.json({ error: "Google PageSpeed is temporarily rate-limiting checks. Try again shortly." }, { status: 429 });
        }
        if (response.status === 403) {
          return Response.json({ error: "Google PageSpeed denied this request. Add a PageSpeed API key in Vercel and try again." }, { status: 502 });
        }
        return Response.json({ error: "Google PageSpeed could not analyze this page. Try again later." }, { status: 502 });
      }

      const data = await response.json();
      const lighthouse = data.lighthouseResult || {};
      const audits = lighthouse.audits || {};
      const categories = lighthouse.categories || {};
      const performanceScore = scoreFor(categories.performance);
      if (performanceScore === null) {
        return Response.json({ error: "Google PageSpeed returned no performance report for this page." }, { status: 502 });
      }

      const metric = (id) => audits[id]?.displayValue || null;
      const opportunities = Object.values(audits)
        .filter((audit) => audit && audit.details?.type === "opportunity" && audit.score !== null && audit.score < 1)
        .sort((a, b) => (a.score || 0) - (b.score || 0))
        .slice(0, 8)
        .map((audit) => ({
          title: cleanText(audit.title),
          description: cleanText(audit.description),
          savings: audit.displayValue || ""
        }));

      const experience = data.loadingExperience || {};
      const fieldMetrics = experience.metrics || {};
      const fieldData = Object.keys(fieldMetrics).length ? {
        overallCategory: experience.overall_category || null,
        metrics: Object.fromEntries(Object.entries(fieldMetrics).map(([name, item]) => [name, {
          category: item.category || null,
          percentile: item.percentile ?? null
        }]))
      } : null;

      return Response.json({
        url: data.id || url.toString(),
        strategy,
        scores: {
          performance: performanceScore,
          accessibility: scoreFor(categories.accessibility),
          bestPractices: scoreFor(categories["best-practices"]),
          seo: scoreFor(categories.seo)
        },
        metrics: {
          firstContentfulPaint: metric("first-contentful-paint"),
          largestContentfulPaint: metric("largest-contentful-paint"),
          cumulativeLayoutShift: metric("cumulative-layout-shift"),
          totalBlockingTime: metric("total-blocking-time"),
          speedIndex: metric("speed-index")
        },
        fieldData,
        opportunities
      });
    } catch (error) {
      return Response.json(
        { error: error && error.message ? error.message : "The PageSpeed check could not be completed." },
        { status: 400 }
      );
    }
  }
};

