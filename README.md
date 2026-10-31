# GBP Tracker by Trexivo — Redesign

This version uses the Trexivo logo image in the dashboard and keeps the live SerpApi Google Maps scan on Vercel. Keep the logo at `assets/trexivo-logo.png` so it appears on the page.

## Upload it to the existing GitHub repository

1. Download and unzip this package.
2. Open your repository: https://github.com/ankittaak/gbpranktracker.github.io
3. Replace the existing `index.html` in the repository root with this package's `index.html`.
4. Upload the `assets` folder with `assets/trexivo-logo.png` to the repository root.
5. Keep the API file at exactly `api/check-rank.js`. If your repository already has this file, replace it with the included version. Do not move it into another folder.
6. Commit the changes to the `main` branch.
7. Vercel should start a deployment from the new GitHub commit. Wait until the deployment says **Ready**, then open your Vercel site and refresh it.

## Keep your SerpApi key private

In Vercel, open **Project Settings → Environment Variables**. Keep the variable name exactly:

`RANK_API_KEY`

Paste your SerpApi key into its **Value**, select **Production** (and **Preview** if you use preview deployments), save it, then redeploy. Never paste the key into `index.html` or commit it to GitHub.

## Using a scan

Fill in your Google Business Profile name, search keyword, city, and country, then select **Run scan**. Use a city or region such as `Dehradun`, not a full street address. The page calls `/api/check-rank` on your Vercel site; opening the HTML directly or hosting it only on GitHub Pages will not run the private API function.

The results are the listings returned by the Google Maps search for that specific keyword and market. Local rankings can vary by location and time.

