// Best-effort mapping from a detection's destination hostname to a
// human-readable service/vendor name (e.g. "drive.google.com" -> "Google
// Drive"). Only ever looks at hostnames -- dst_domain is either the TLS
// SNI / HTTP Host header extracted live (ml/collector.py) or a raw IP when
// no hostname could be captured, and a bare IP can't be safely attributed
// to a vendor, so those are surfaced as "Unknown" rather than guessed.
//
// Keys are matched as the hostname itself or as a parent domain of it
// (longest match wins), so both "drive.google.com" and an unlisted host
// like "mail.google.com" resolve sensibly off a handful of entries.
const SERVICE_MAP: Record<string, string> = {
    // Google
    'google.com': 'Google', 'googleapis.com': 'Google', 'gstatic.com': 'Google',
    'googleusercontent.com': 'Google', 'googlevideo.com': 'YouTube', 'youtube.com': 'YouTube',
    'ytimg.com': 'YouTube', 'drive.google.com': 'Google Drive', 'docs.google.com': 'Google Docs',
    'mail.google.com': 'Gmail', 'gmail.com': 'Gmail',

    // Microsoft
    'microsoft.com': 'Microsoft', 'office.com': 'Microsoft 365', 'office365.com': 'Microsoft 365',
    'live.com': 'Microsoft', 'outlook.com': 'Outlook', 'onedrive.com': 'OneDrive',
    'sharepoint.com': 'SharePoint', 'teams.microsoft.com': 'Microsoft Teams', 'azure.com': 'Microsoft Azure',
    'windows.net': 'Microsoft Azure', 'skype.com': 'Skype',

    // Cloud storage / file sharing (common shadow-IT risk)
    'dropbox.com': 'Dropbox', 'dropboxusercontent.com': 'Dropbox', 'box.com': 'Box',
    'wetransfer.com': 'WeTransfer', 'mega.nz': 'Mega', 'mediafire.com': 'MediaFire',
    'icloud.com': 'iCloud', 'apple.com': 'Apple',

    // Communication / collaboration
    'slack.com': 'Slack', 'zoom.us': 'Zoom', 'discord.com': 'Discord', 'discordapp.com': 'Discord',
    'telegram.org': 'Telegram', 't.me': 'Telegram', 'whatsapp.com': 'WhatsApp', 'whatsapp.net': 'WhatsApp',
    'webex.com': 'Cisco Webex', 'gotomeeting.com': 'GoToMeeting',

    // Dev / infra
    'github.com': 'GitHub', 'githubusercontent.com': 'GitHub', 'gitlab.com': 'GitLab',
    'bitbucket.org': 'Bitbucket', 'amazonaws.com': 'AWS', 'awsstatic.com': 'AWS',
    'digitalocean.com': 'DigitalOcean', 'cloudflare.com': 'Cloudflare', 'heroku.com': 'Heroku',
    'atlassian.net': 'Atlassian', 'atlassian.com': 'Atlassian',

    // Productivity / SaaS
    'notion.so': 'Notion', 'trello.com': 'Trello', 'asana.com': 'Asana', 'salesforce.com': 'Salesforce',
    'adobe.com': 'Adobe', 'canva.com': 'Canva', 'anthropic.com': 'Anthropic (Claude)', 'openai.com': 'OpenAI',

    // Remote access (common unsanctioned-IT risk)
    'teamviewer.com': 'TeamViewer', 'anydesk.com': 'AnyDesk', 'logmein.com': 'LogMeIn',

    // Social / streaming
    'facebook.com': 'Facebook', 'fbcdn.net': 'Facebook', 'instagram.com': 'Instagram',
    'twitter.com': 'Twitter/X', 'x.com': 'Twitter/X', 'linkedin.com': 'LinkedIn', 'reddit.com': 'Reddit',
    'tiktok.com': 'TikTok', 'netflix.com': 'Netflix', 'spotify.com': 'Spotify',
}

// Two-label public suffixes where the "root domain" needs three labels
// (e.g. "example.co.uk", not "co.uk"). Only used by the unmatched-hostname
// fallback below, not by the curated SERVICE_MAP lookup.
const COMPOUND_TLDS = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.nz', 'co.in', 'co.za', 'com.au', 'com.br',
])

function isIpAddress(host: string): boolean {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')
}

function rootLabel(host: string): string {
    const parts = host.split('.')
    if (parts.length <= 2) return parts[0]
    const lastTwo = parts.slice(-2).join('.')
    if (COMPOUND_TLDS.has(lastTwo) && parts.length >= 3) return parts[parts.length - 3]
    return parts[parts.length - 2]
}

/**
 * Matches a destination hostname against a known-applications domain list
 * (exact match or subdomain), mirroring ml/model.py's is_sanctioned() so the
 * "Known" badge on Applications/Devices reflects the same rule the ML
 * allowlist uses server-side. Raw IPs never match -- a bare IP can't be
 * verified as a specific known service.
 */
export function matchesKnownDomain(dst: string | null | undefined, knownDomains: string[]): string | null {
    if (!dst) return null
    const host = dst.trim().toLowerCase().replace(/\.$/, '')
    if (!host || isIpAddress(host)) return null
    for (const entry of knownDomains) {
        const e = entry.trim().toLowerCase().replace(/\.$/, '')
        if (e && (host === e || host.endsWith('.' + e))) return entry
    }
    return null
}

export interface ResolvedService {
    name: string
    /** true when matched against the curated vendor list; false for a best-effort
     *  hostname-derived guess or the "Unknown" raw-IP case. */
    recognized: boolean
}

/**
 * Resolves a detection's destination (Detection.dst_domain) to a
 * human-readable service name. Returns null only when there is no
 * destination at all.
 */
export function resolveService(dst: string | null | undefined): ResolvedService | null {
    if (!dst) return null
    const host = dst.trim().toLowerCase()
    if (!host) return null
    if (isIpAddress(host)) return { name: 'Unknown', recognized: false }

    const labels = host.split('.')
    for (let i = 0; i < labels.length - 1; i++) {
        const candidate = labels.slice(i).join('.')
        const match = SERVICE_MAP[candidate]
        if (match) return { name: match, recognized: true }
    }

    const label = rootLabel(host)
    if (!label) return { name: 'Unknown', recognized: false }
    return { name: label.charAt(0).toUpperCase() + label.slice(1), recognized: false }
}
