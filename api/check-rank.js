const MAX_START = 100;
const MAX_PAGES = 6;

function normalize(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function findBusinessIndex(places, businessName) {
  return places.findIndex((place) => normalize(place.title).includes(businessName));
}

function selectDisplayResults(places, matchIndex) {
  if (matchIndex < 0) return places.slice(0, 10);

  const indexes = new Set();
  for (let index = 0; index < Math.min(3, places.length); index += 1) {
    indexes.add(index);
  }

  const firstNearby = Math.max(0, matchIndex - 2);
  const lastNearby = Math.min(places.length - 1, matchIndex + 2);
  for (let index = firstNearby; index <= lastNearby; index += 1) {
    indexes.add(index);
  }

  return Array.from(indexes)
    .sort((a, b) => a - b)
    .map((index) => places[index]);
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return Response.json({ error: "Use POST for scans." }, { status: 405 });
    }

    const apiKey = process.env.RANK_API_KEY;
    if (!apiKey) {
      return Response.json(
        { error: "RANK_API_KEY is missing from Vercel settings." },
        { status: 500 }
      );
    }

    try {
      const input = await request.json();
      const keyword = String(input.keyword || "").trim();
      const business = String(input.business || "").trim();
      const city = String(input.city || "").trim();
      const country = String(input.country || "").trim();

      if (!keyword || !business || !city) {
        return Response.json(
          { error: "A keyword, business name, and city are required." },
          { status: 400 }
        );
      }

      const location = [city, country].filter(Boolean).join(", ");
      const initialParams = new URLSearchParams({
        engine: "google_maps",
        type: "search",
        q: keyword,
        location,
        z: "14",
        api_key: apiKey
      });

      let nextPageUrl = "https://serpapi.com/search.json?" + initialParams.toString();
      let latestData = null;
      let lastOffset = 0;
      let requestsMade = 0;
      const places = [];
      const businessName = normalize(business);

      while (nextPageUrl && requestsMade < MAX_PAGES) {
        const pageUrl = new URL(nextPageUrl);
        if (pageUrl.protocol !== "https:" || pageUrl.hostname !== "serpapi.com" || pageUrl.pathname !== "/search.json") {
          throw new Error("SerpApi returned an invalid next-page URL.");
        }
        pageUrl.searchParams.set("api_key", apiKey);

        const response = await fetch(pageUrl.toString());
        const data = await response.json();
        if (!response.ok || (data.error && !Array.isArray(data.local_results))) {
          return Response.json(
            { error: data.error || "SerpApi could not complete the search." },
            { status: 502 }
          );
        }

        latestData = data;
        const offset = Number(pageUrl.searchParams.get("start")) || 0;
        lastOffset = offset;
        const pagePlaces = Array.isArray(data.local_results) ? data.local_results : [];

        pagePlaces.forEach((place, index) => {
          places.push({
            position: offset + index + 1,
            title: place.title || "",
            address: place.address || "",
            rating: place.rating ?? null,
            place_id: place.place_id || "",
            data_id: place.data_id || ""
          });
        });

        requestsMade += 1;

        const matchIndex = findBusinessIndex(places, businessName);
        const hasTwoListingsBelow = matchIndex >= 0 && places.length >= matchIndex + 3;
        if (hasTwoListingsBelow) break;

        const next = data.serpapi_pagination && data.serpapi_pagination.next;
        if (!next || requestsMade >= MAX_PAGES) break;

        const parsedNext = new URL(next);
        const nextOffset = Number(parsedNext.searchParams.get("start"));
        if (!Number.isFinite(nextOffset) || nextOffset <= offset || nextOffset > MAX_START) break;
        nextPageUrl = parsedNext.toString();
      }

      const matchIndex = findBusinessIndex(places, businessName);
      const displayResults = selectDisplayResults(places, matchIndex);
      const scanLimitReached = matchIndex < 0 && requestsMade >= MAX_PAGES && lastOffset >= MAX_START;

      return Response.json({
        keyword,
        location,
        rank: matchIndex >= 0 ? places[matchIndex].position : null,
        checked: places.length,
        scannedResults: places,
        displayResults,
        results: displayResults,
        scanLimitReached,
        paginationPages: requestsMade,
        searchState: latestData && latestData.search_information
          ? latestData.search_information.local_results_state || ""
          : ""
      });
    } catch {
      return Response.json(
        { error: "The scan failed. Check the Vercel function logs." },
        { status: 500 }
      );
    }
  }
};
