const API_VERSION = "v26";
const RATE_LIMIT = 8;
const RATE_WINDOW_MS = 60_000;
const requestsByClient = new Map();

const COUNTRIES = {
  IN: "India",
  US: "United States",
  GB: "United Kingdom",
  CA: "Canada",
  AU: "Australia",
  AE: "United Arab Emirates",
  SG: "Singapore",
  BD: "Bangladesh",
  NZ: "New Zealand",
  ZA: "South Africa",
  IE: "Ireland",
  DE: "Germany",
  FR: "France",
  ES: "Spain",
  BR: "Brazil"
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function allowRequest(request) {
  const now = Date.now();
  const key = (request.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
  const current = requestsByClient.get(key);
  if (!current || current.resetAt <= now) {
    requestsByClient.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (current.count >= RATE_LIMIT) return false;
  current.count += 1;
  return true;
}

function cleanText(value, maxLength = 120) {
  return String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function unique(values) {
  return Array.from(new Map(values.map((value) => [value.toLowerCase(), value])).values());
}

async function readJson(response) {
  try { return await response.json(); }
  catch { return {}; }
}

async function createAccessToken() {
  const form = new URLSearchParams({
    client_id: process.env.GOOGLE_ADS_CLIENT_ID,
    client_secret: process.env.GOOGLE_ADS_CLIENT_SECRET,
    refresh_token: process.env.GOOGLE_ADS_REFRESH_TOKEN,
    grant_type: "refresh_token"
  });
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
    signal: AbortSignal.timeout(12_000)
  });
  const data = await readJson(response);
  if (!response.ok || !data.access_token) {
    throw new Error("Google Ads sign-in credentials were rejected. Check the OAuth values in Vercel.");
  }
  return data.access_token;
}

async function googleAdsRequest(path, accessToken, body) {
  const customerId = process.env.GOOGLE_ADS_CUSTOMER_ID.replace(/-/g, "");
  const headers = {
    Authorization: "Bearer " + accessToken,
    "Content-Type": "application/json"
  };
  const managerId = String(process.env.GOOGLE_ADS_LOGIN_CUSTOMER_ID || "").replace(/-/g, "");
  if (managerId) headers["login-customer-id"] = managerId;

  // Google Ads access is now associated with the Cloud project. Developer tokens were sunset in 2026.
  const response = await fetch("https://googleads.googleapis.com/" + API_VERSION + path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000)
  });
  const data = await readJson(response);
  if (!response.ok) {
    const error = new Error(data.error?.message || "Google Ads could not complete keyword research.");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function findGeoTarget(accessToken, location, countryCode) {
  if (!countryCode && !location) return null;
  if (location && !countryCode) {
    throw new Error("Choose a country for the location you entered.");
  }
  if (countryCode && !COUNTRIES[countryCode]) {
    throw new Error("Choose a supported target country.");
  }

  const locationName = location ? location.split(",")[0].trim() : COUNTRIES[countryCode];
  const data = await googleAdsRequest("/geoTargetConstants:suggest", accessToken, {
    locale: "en",
    countryCode,
    locationNames: { names: [locationName] }
  });
  const suggestions = (data.geoTargetConstantSuggestions || [])
    .filter((item) => item.geoTargetConstant?.resourceName
      && (!item.geoTargetConstant.status || item.geoTargetConstant.status === "ENABLED")
      && (!countryCode || item.geoTargetConstant.countryCode === countryCode));

  if (!suggestions.length) {
    throw new Error("Google Ads could not match that location. Try a city or region name in the selected country.");
  }

  const exactName = locationName.toLowerCase();
  suggestions.sort((a, b) => {
    const aName = String(a.geoTargetConstant.name || "").toLowerCase();
    const bName = String(b.geoTargetConstant.name || "").toLowerCase();
    const aExact = aName === exactName ? 1 : 0;
    const bExact = bName === exactName ? 1 : 0;
    const aCity = a.geoTargetConstant.targetType === "City" ? 1 : 0;
    const bCity = b.geoTargetConstant.targetType === "City" ? 1 : 0;
    return bExact - aExact || bCity - aCity || Number(b.reach || 0) - Number(a.reach || 0);
  });
  return suggestions[0].geoTargetConstant;
}

function userFacingGoogleError(error) {
  if (error.status === 401 || error.status === 403) {
    return "Google Ads denied this request. Check that the Cloud project used for OAuth has Basic access or higher for Keyword Planning.";
  }
  if (error.status === 404) {
    return "Google Ads could not find that customer account. Check the customer ID in Vercel.";
  }
  if (error.status === 429) {
    return "Google Ads is rate-limiting keyword requests. Wait a moment and try again.";
  }
  return error.message || "Google Ads keyword research failed. Please try again.";
}

export default {
  async fetch(request) {
    if (request.method !== "POST") return json({ error: "Use POST for keyword research." }, 405);
    if (!allowRequest(request)) return json({ error: "Keyword research is temporarily rate-limited. Try again in a minute." }, 429);

    const required = ["GOOGLE_ADS_CLIENT_ID", "GOOGLE_ADS_CLIENT_SECRET", "GOOGLE_ADS_REFRESH_TOKEN", "GOOGLE_ADS_CUSTOMER_ID"];
    const missing = required.filter((key) => !process.env[key]);
    if (missing.length) {
      return json({
        code: "NOT_CONFIGURED",
        error: "Google Ads is not connected yet. Add the Google Ads OAuth settings and customer ID in Vercel to get measured keyword data."
      }, 503);
    }

    const customerId = String(process.env.GOOGLE_ADS_CUSTOMER_ID).replace(/-/g, "");
    if (!/^\d{10}$/.test(customerId)) return json({ error: "The Google Ads customer ID must contain 10 digits." }, 503);

    try {
      const input = await request.json();
      const businessName = cleanText(input.businessName, 100);
      const services = unique((Array.isArray(input.services) ? input.services : [])
        .map((value) => cleanText(value, 80)).filter(Boolean)).slice(0, 5);
      const location = cleanText(input.location, 100);
      const countryCode = String(input.countryCode || "").toUpperCase();
      const language = /^languageConstants\/\d+$/.test(String(input.language || ""))
        ? String(input.language)
        : "languageConstants/1000";
      const limit = [50, 100, 200, 500].includes(Number(input.limit)) ? Number(input.limit) : 50;

      if (!businessName) return json({ error: "Enter the business name." }, 400);
      if (!services.length) return json({ error: "Enter at least one service or product." }, 400);

      const accessToken = await createAccessToken();
      const geoTarget = await findGeoTarget(accessToken, location, countryCode);
      const keywordSeeds = unique([
        businessName,
        ...services,
        ...services.map((service) => location ? service + " " + location.split(",")[0].trim() : "")
      ].map((value) => cleanText(value, 100)).filter(Boolean)).slice(0, 20);

      const ideaRequest = {
        language,
        keywordPlanNetwork: "GOOGLE_SEARCH",
        includeAdultKeywords: false,
        pageSize: limit,
        historicalMetricsOptions: { includeAverageCpc: true },
        keywordSeed: { keywords: keywordSeeds }
      };
      if (geoTarget) ideaRequest.geoTargetConstants = [geoTarget.resourceName];

      const [ideasData, customerData] = await Promise.all([
        googleAdsRequest("/customers/" + customerId + ":generateKeywordIdeas", accessToken, ideaRequest),
        googleAdsRequest("/customers/" + customerId + "/googleAds:search", accessToken, {
          query: "SELECT customer.currency_code FROM customer LIMIT 1"
        }).catch(() => null)
      ]);

      const currencyCode = customerData?.results?.[0]?.customer?.currencyCode || null;
      const results = (ideasData.results || []).slice(0, limit).map((item) => {
        const metrics = item.keywordIdeaMetrics || {};
        return {
          keyword: item.text || "",
          avgMonthlySearches: metrics.avgMonthlySearches ?? null,
          competition: metrics.competition || null,
          competitionIndex: metrics.competitionIndex ?? null,
          averageCpcMicros: metrics.averageCpcMicros ?? null,
          lowTopOfPageBidMicros: metrics.lowTopOfPageBidMicros ?? null,
          highTopOfPageBidMicros: metrics.highTopOfPageBidMicros ?? null,
          currencyCode
        };
      }).filter((item) => item.keyword);

      return json({
        source: "Google Ads Keyword Planner",
        currencyCode,
        location: geoTarget?.name || "All locations",
        requestedLimit: limit,
        totalIdeas: ideasData.totalSize || results.length,
        ideas: results
      });
    } catch (error) {
      return json({ error: userFacingGoogleError(error) }, error.status && error.status >= 400 && error.status < 500 ? error.status : 502);
    }
  }
};

