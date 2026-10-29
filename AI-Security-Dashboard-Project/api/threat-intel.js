export default async function handler(_request, response) {
  response.setHeader('Cache-Control', 'public, s-maxage=900, stale-while-revalidate=3600');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');

  try {
    // Use CISA's official GitHub mirror. It tracks the catalog and remains
    // available to serverless runtimes that cannot fetch the CISA site directly.
    const feedResponse = await fetch('https://raw.githubusercontent.com/CISAGov/kev-data/develop/known_exploited_vulnerabilities.json', {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(12000),
    });
    if (!feedResponse.ok) throw new Error(`CISA returned HTTP ${feedResponse.status}`);

    const catalog = await feedResponse.json();
    if (!Array.isArray(catalog.vulnerabilities)) throw new Error('CISA feed format was not recognized');

    response.status(200).json({
      source: 'CISA Known Exploited Vulnerabilities Catalog',
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      feedUrl: 'https://github.com/CISAGov/kev-data',
      catalogVersion: catalog.catalogVersion || null,
      sourceReleasedAt: catalog.dateReleased || null,
      totalEntries: catalog.count || catalog.vulnerabilities.length,
      fetchedAt: new Date().toISOString(),
      vulnerabilities: catalog.vulnerabilities,
    });
  } catch (error) {
    response.status(502).json({
      error: 'The public CISA catalog could not be loaded right now.',
      details: error instanceof Error ? error.message : 'Unknown upstream error',
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    });
  }
}
