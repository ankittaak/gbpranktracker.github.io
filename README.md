# GBP Tracker by Trexivo

A responsive GitHub Pages dashboard demo for local Google Business Profile ranking. It runs as a single static page, with no server setup required.

## Publish with GitHub Pages

1. Download and extract `GBP-Tracker-by-Trexivo-GitHub-Pages.zip`.
2. On GitHub, create a new **public** repository named `gbp-tracker-by-trexivo`.
3. In the repository, choose **Add file → Upload files**. Upload `index.html` and `README.md` from the extracted folder, then commit the files to the `main` branch.
4. Open **Settings → Pages**.
5. Under **Build and deployment**, choose **Deploy from a branch**. Select branch `main` and folder `/(root)`, then choose **Save**.
6. After GitHub finishes publishing, open:

   `https://YOUR-GITHUB-USERNAME.github.io/gbp-tracker-by-trexivo/`

GitHub's guide: [Creating a GitHub Pages site](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site).

## What works in this demo

- Choose a sample location in Chicago, London, Mumbai, Dubai, Singapore, or Sydney.
- Add any business location worldwide by entering its business name, area, city, and country. The dashboard updates its location labels, sample metrics, grid, and keyword table.
- Add keywords, show each keyword in the grid, change the sample period, and refresh the sample grid.
- Your custom locations, selected location, and added keywords are saved in your browser only.

The rankings and scans are **sample data**. This demo does not look up real Google results or connect to a ranking provider. To add live ranking checks later, connect the page to a backend service and keep any provider API key in that backend's environment settings. Never put a secret API key in `index.html` or in a public GitHub repository.

The icons load from the pinned Lucide CDN script in `index.html`; the dashboard itself is static and needs no build step.
