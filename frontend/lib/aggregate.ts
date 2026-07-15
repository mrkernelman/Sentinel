import { detectionsApi } from './api'
import type { Detection, DetectionSource, RiskLevel, ShadowItType, DeviceSighting, KnownDevice } from './types'

const RISK_RANK: Record<RiskLevel, number> = { high: 3, medium: 2, low: 1 }
const higherRisk = (a: RiskLevel, b: RiskLevel) => (RISK_RANK[b] > RISK_RANK[a] ? b : a)

// Pages through /api/detections (server caps per_page at 100) up to maxRows,
// used to build client-side device/application aggregates without new backend endpoints.
export async function fetchAllDetections(maxRows = 500): Promise<{ rows: Detection[]; total: number }> {
    const perPage = 100
    const first = await detectionsApi.list({ page: 1, per_page: perPage })
    const total: number = first.data.total || 0
    const rows: Detection[] = [...(first.data.detections || [])]
    const pages = Math.min(Math.ceil(total / perPage), Math.ceil(maxRows / perPage))

    if (pages > 1) {
        const rest = await Promise.all(
            Array.from({ length: pages - 1 }, (_, i) => detectionsApi.list({ page: i + 2, per_page: perPage }))
        )
        for (const res of rest) rows.push(...(res.data.detections || []))
    }
    return { rows: rows.slice(0, maxRows), total }
}

export interface DeviceAggregate {
    src_ip: string | null
    src_mac: string | null
    device_type: string | null
    count: number
    risk: RiskLevel
    lastSeen: string | null
    // Most frequently seen dst_domain for this device, used to surface a
    // "top service" (see lib/services.ts) even though a device can talk to
    // many destinations -- this is a representative one, not the only one.
    topDestination: string | null
    // undefined until a device_sightings row exists for this device (e.g. a
    // device only known from dataset-run detections was never actually
    // "seen" by the live collector).
    firstSeen?: string
    source?: DetectionSource
    // Set when this device matches an admin-curated known_devices entry
    // (Known Assets page) by src_ip or src_mac.
    knownName?: string | null
}

export function groupByDevice(rows: Detection[]): DeviceAggregate[] {
    const map = new Map<string, DeviceAggregate>()
    const destCounts = new Map<string, Map<string, number>>()
    for (const d of rows) {
        const key = d.src_ip || d.src_mac || 'unknown'
        if (!map.has(key)) {
            map.set(key, {
                src_ip: d.src_ip,
                src_mac: d.src_mac,
                device_type: d.device_type,
                count: 0,
                risk: 'low',
                lastSeen: d.detected_at,
                topDestination: null,
            })
        }
        const entry = map.get(key)!
        entry.count += 1
        entry.risk = higherRisk(entry.risk, d.risk_level || 'low')
        if (d.detected_at && (!entry.lastSeen || d.detected_at > entry.lastSeen)) {
            entry.lastSeen = d.detected_at
        }
        if (d.dst_domain) {
            if (!destCounts.has(key)) destCounts.set(key, new Map())
            const counts = destCounts.get(key)!
            counts.set(d.dst_domain, (counts.get(d.dst_domain) ?? 0) + 1)
        }
    }
    for (const [key, entry] of map) {
        const counts = destCounts.get(key)
        if (counts) {
            entry.topDestination = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]
        }
    }
    return [...map.values()].sort((a, b) => b.count - a.count)
}

// Builds the full Device Inventory: every device the durable sightings
// registry (device_sightings, populated the instant anything is seen on the
// wire) has ever recorded, enriched with detection stats where they exist --
// not just the subset of devices that happen to have triggered an anomaly.
// Also includes devices known only from dataset-run detections (no live
// sighting), and cross-references known_devices for a friendly name.
export function buildDeviceInventory(
    detectionRows: Detection[],
    sightings: DeviceSighting[],
    known: KnownDevice[] = []
): DeviceAggregate[] {
    const fromDetections = groupByDevice(detectionRows)
    const byKey = new Map(fromDetections.map((d) => [d.src_ip || d.src_mac || 'unknown', d]))

    const knownByKey = new Map<string, KnownDevice>()
    for (const k of known) {
        if (k.src_ip) knownByKey.set(k.src_ip, k)
        if (k.src_mac) knownByKey.set(k.src_mac, k)
    }
    const knownNameFor = (ip: string | null, mac: string | null) =>
        (ip && knownByKey.get(ip)?.name) || (mac && knownByKey.get(mac)?.name) || null

    const seenKeys = new Set<string>()
    const result: DeviceAggregate[] = []

    for (const s of sightings) {
        const key = s.src_ip || s.src_mac || 'unknown'
        seenKeys.add(key)
        const det = byKey.get(key)
        result.push({
            src_ip: s.src_ip,
            src_mac: s.src_mac,
            device_type: det?.device_type ?? null,
            count: det?.count ?? 0,
            risk: det?.risk ?? 'low',
            lastSeen: det?.lastSeen ?? s.last_seen,
            topDestination: det?.topDestination ?? null,
            firstSeen: s.first_seen,
            source: s.source,
            knownName: knownNameFor(s.src_ip, s.src_mac),
        })
    }
    // Devices only known from detections (e.g. a dataset-run row never
    // actually sighted live).
    for (const d of fromDetections) {
        const key = d.src_ip || d.src_mac || 'unknown'
        if (seenKeys.has(key)) continue
        result.push({ ...d, knownName: knownNameFor(d.src_ip, d.src_mac) })
    }

    return result.sort((a, b) => b.count - a.count)
}

export interface ApplicationAggregate {
    dst_domain: string
    shadow_it_type: ShadowItType | null
    count: number
    risk: RiskLevel
    lastSeen: string | null
}

export function groupByApplication(rows: Detection[]): ApplicationAggregate[] {
    const map = new Map<string, ApplicationAggregate>()
    for (const d of rows) {
        const key = d.dst_domain || 'Unknown'
        if (!map.has(key)) {
            map.set(key, {
                dst_domain: key,
                shadow_it_type: d.shadow_it_type,
                count: 0,
                risk: 'low',
                lastSeen: d.detected_at,
            })
        }
        const entry = map.get(key)!
        entry.count += 1
        entry.risk = higherRisk(entry.risk, d.risk_level || 'low')
        if (d.detected_at && (!entry.lastSeen || d.detected_at > entry.lastSeen)) {
            entry.lastSeen = d.detected_at
        }
    }
    return [...map.values()].sort((a, b) => b.count - a.count)
}
