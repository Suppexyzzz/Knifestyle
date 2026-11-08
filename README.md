# KnifeStyle License Server

ASP.NET Core 8 license API and static admin/registration site.

## Railway

Deploy this repository with the root `Dockerfile`. Attach a persistent volume at `/data` so license keys and accounts survive deploys. Set `KNIFESTYLE_SETUP_KEY` as a private service variable before first use. Open the public site and create the owner account through the setup panel; never commit the setup key or `data/license-data.json`.

The image seeds its initial mod release from `releases/knifestyle-1.0.0.jar`.

## Netlify

The Netlify site publishes `wwwroot`. The `/api/*` rewrite in `netlify.toml` must target the public HTTPS Railway service domain.
