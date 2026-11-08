# KnifeStyle

KnifeStyle admin and registration website with a serverless license API.

## Netlify deployment

The site publishes `wwwroot`; `netlify/functions/api.ts` keeps the existing `/api/*` endpoints for the website and loader. Netlify Database provisions PostgreSQL and applies the schema in `netlify/database/migrations`. The initial JAR is bundled privately with the API function and copied into the database on first use, so it is not exposed as a public static file.

Before publishing, create a secret environment variable named `KNIFESTYLE_SETUP_KEY` in Netlify with the Functions runtime scope. Open the deployed site once to initialize the Owner account through its setup panel. The setup key is only needed for that initial creation; after the Owner exists, remove the variable.

The admin release upload endpoint accepts JAR files up to 4.5 MB to stay within Netlify's binary function request limit.
