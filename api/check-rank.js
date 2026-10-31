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
      const area = String(input.area || "").trim();
      const city = String(input.city || "").trim();
      const country = String(input.country || "").trim();

      if (!keyword || !business || !city) {
        return Response.json(
          { error: "A keyword, business name, and city are required." },
          { status: 400 }
        );
      }

      const location = [area, city, country].filter(Boolean).join(", ");
      const params = new URLSearchParams({
        engine: "google_maps",
        type: "search",
        q: keyword,
        location,
        z: "14",
        api_key: apiKey
      });

      const response = await fetch(
        `https://serpapi.com/search.json?${params}`
      );
      const data = await response.json();

      if (!response.ok || data.error) {
        return Response.json(
          { error: data.error || "SerpApi could not complete the search." },
          { status: 502 }
        );
      }

      const places = Array.isArray(data.local_results)
        ? data.local_results
        : [];
      const normalize = (value) =>
        String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
      const businessName = normalize(business);

      const matchIndex = places.findIndex((place) =>
        normalize(place.title).includes(businessName)
      );

      return Response.json({
        keyword,
        location,
        rank:
          matchIndex >= 0
            ? Number(places[matchIndex].position || matchIndex + 1)
            : null,
        checked: places.length,
        results: places.slice(0, 10).map((place, index) => ({
          position: Number(place.position || index + 1),
          title: place.title || "",
          address: place.address || "",
          rating: place.rating ?? null
        }))
      });
    } catch {
      return Response.json(
        { error: "The scan failed. Check the Vercel function logs." },
        { status: 500 }
      );
    }
  }
};
