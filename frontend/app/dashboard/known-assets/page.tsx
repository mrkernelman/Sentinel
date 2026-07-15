'use client'
import { Suspense, useCallback, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { motion } from 'framer-motion'
import GlassCard from '@/components/ui/GlassCard'
import { knownAssetsApi, apiErrorMessage } from '@/lib/api'
import { isAdmin } from '@/lib/auth'
import { ShieldCheck, Monitor, Package, Trash2, Plus, Loader2, X } from 'lucide-react'
import type { KnownDevice, KnownApplication } from '@/lib/types'

function formatDate(iso: string) {
    return new Date(iso).toLocaleDateString() + ' ' + new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function KnownAssetsInner() {
    const router = useRouter()
    const searchParams = useSearchParams()
    useEffect(() => { if (!isAdmin()) router.push('/dashboard') }, [router])

    const [devices, setDevices] = useState<KnownDevice[]>([])
    const [apps, setApps] = useState<KnownApplication[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    const [devForm, setDevForm] = useState({ src_ip: '', src_mac: '', name: '', notes: '' })
    const [appForm, setAppForm] = useState({ domain: '', name: '', notes: '' })
    const [showDevForm, setShowDevForm] = useState(false)
    const [showAppForm, setShowAppForm] = useState(false)
    const [saving, setSaving] = useState(false)

    const load = useCallback(async () => {
        setLoading(true)
        try {
            const [devRes, appRes] = await Promise.all([
                knownAssetsApi.devices(),
                knownAssetsApi.applications(),
            ])
            setDevices(devRes.data.devices || [])
            setApps(appRes.data.applications || [])
        } catch (err) {
            console.error(err)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load() }, [load])

    // Prefill + open the relevant form when arriving via a "Mark as Known"
    // link from the Devices or Applications page.
    useEffect(() => {
        const ip = searchParams.get('addDeviceIp')
        const mac = searchParams.get('addDeviceMac')
        if (ip || mac) {
            setDevForm((f) => ({ ...f, src_ip: ip || '', src_mac: mac || '' }))
            setShowDevForm(true)
        }
        const domain = searchParams.get('addAppDomain')
        if (domain) {
            setAppForm((f) => ({ ...f, domain }))
            setShowAppForm(true)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    const addDevice = async () => {
        setError(''); setSaving(true)
        try {
            await knownAssetsApi.addDevice({
                src_ip: devForm.src_ip || undefined,
                src_mac: devForm.src_mac || undefined,
                name: devForm.name,
                notes: devForm.notes || undefined,
            })
            setDevForm({ src_ip: '', src_mac: '', name: '', notes: '' })
            setShowDevForm(false)
            await load()
        } catch (err) {
            setError(apiErrorMessage(err, 'Could not add known device'))
        } finally {
            setSaving(false)
        }
    }

    const addApp = async () => {
        setError(''); setSaving(true)
        try {
            await knownAssetsApi.addApplication({
                domain: appForm.domain,
                name: appForm.name,
                notes: appForm.notes || undefined,
            })
            setAppForm({ domain: '', name: '', notes: '' })
            setShowAppForm(false)
            await load()
        } catch (err) {
            setError(apiErrorMessage(err, 'Could not add known application'))
        } finally {
            setSaving(false)
        }
    }

    const removeDevice = async (id: number) => {
        try { await knownAssetsApi.removeDevice(id); setDevices((d) => d.filter((x) => x.id !== id)) }
        catch (err) { console.error(err) }
    }
    const removeApp = async (id: number) => {
        try { await knownAssetsApi.removeApplication(id); setApps((a) => a.filter((x) => x.id !== id)) }
        catch (err) { console.error(err) }
    }

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
                    <ShieldCheck className="w-8 h-8 text-emerald-500" />
                    Known Assets
                </h1>
                <p className="text-sm text-slate-700 dark:text-slate-400">
                    Devices and applications your organization already knows about. Known applications suppress
                    future ML alerts for that destination; known devices get a friendly name across the dashboard.
                </p>
            </div>

            {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/25 text-sm text-red-400">{error}</div>
            )}

            {/* Known Devices */}
            <GlassCard className="p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <Monitor className="w-5 h-5 text-blue-400" /> Known Devices
                    </h3>
                    <motion.button whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                        onClick={() => setShowDevForm((s) => !s)}
                        className="text-xs px-3 py-2 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 border border-blue-500/25 transition-all font-medium flex items-center gap-1.5">
                        {showDevForm ? <X className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
                        {showDevForm ? 'Cancel' : 'Add Known Device'}
                    </motion.button>
                </div>

                {showDevForm && (
                    <div className="mb-4 p-4 rounded-lg bg-white/3 border border-white/10 grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <input placeholder="Source IP (e.g. 172.16.249.2)" value={devForm.src_ip}
                            onChange={(e) => setDevForm({ ...devForm, src_ip: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white" />
                        <input placeholder="MAC Address (optional)" value={devForm.src_mac}
                            onChange={(e) => setDevForm({ ...devForm, src_mac: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white" />
                        <input placeholder="Display name (e.g. Finance Laptop #3)" value={devForm.name}
                            onChange={(e) => setDevForm({ ...devForm, name: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white sm:col-span-2" />
                        <input placeholder="Notes (optional)" value={devForm.notes}
                            onChange={(e) => setDevForm({ ...devForm, notes: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white sm:col-span-2" />
                        <button onClick={addDevice} disabled={saving || !devForm.name || (!devForm.src_ip && !devForm.src_mac)}
                            className="sm:col-span-2 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-all">
                            {saving ? 'Saving…' : 'Save Known Device'}
                        </button>
                    </div>
                )}

                {loading ? (
                    <div className="text-center py-8"><Loader2 className="w-5 h-5 animate-spin mx-auto text-blue-400" /></div>
                ) : devices.length === 0 ? (
                    <p className="text-sm text-slate-500 py-4">No known devices yet — add the devices your organization has issued.</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="border-b border-slate-200 dark:border-white/10">
                                <tr className="text-xs text-slate-900 dark:text-slate-500 font-medium">
                                    <th className="text-left py-2 px-3">Name</th>
                                    <th className="text-left py-2 px-3">Source IP</th>
                                    <th className="text-left py-2 px-3">MAC</th>
                                    <th className="text-left py-2 px-3">Notes</th>
                                    <th className="text-left py-2 px-3">Added</th>
                                    <th className="py-2 px-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {devices.map((d) => (
                                    <tr key={d.id} className="border-b border-slate-200 dark:border-white/5">
                                        <td className="py-2 px-3 text-xs font-medium text-slate-900 dark:text-white">{d.name}</td>
                                        <td className="py-2 px-3 text-xs font-mono text-slate-700 dark:text-slate-300">{d.src_ip || '—'}</td>
                                        <td className="py-2 px-3 text-xs font-mono text-slate-500 dark:text-slate-400">{d.src_mac || '—'}</td>
                                        <td className="py-2 px-3 text-xs text-slate-500 max-w-[200px] truncate">{d.notes || '—'}</td>
                                        <td className="py-2 px-3 text-xs text-slate-500">{formatDate(d.created_at)}</td>
                                        <td className="py-2 px-3 text-right">
                                            <button onClick={() => removeDevice(d.id)} className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-all">
                                                <Trash2 className="w-3.5 h-3.5" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </GlassCard>

            {/* Known Applications */}
            <GlassCard className="p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <Package className="w-5 h-5 text-purple-400" /> Known Applications
                    </h3>
                    <motion.button whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                        onClick={() => setShowAppForm((s) => !s)}
                        className="text-xs px-3 py-2 rounded-lg bg-purple-500/10 text-purple-400 hover:bg-purple-500/20 border border-purple-500/25 transition-all font-medium flex items-center gap-1.5">
                        {showAppForm ? <X className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
                        {showAppForm ? 'Cancel' : 'Add Known Application'}
                    </motion.button>
                </div>

                {showAppForm && (
                    <div className="mb-4 p-4 rounded-lg bg-white/3 border border-white/10 grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <input placeholder="Domain (e.g. slack.com)" value={appForm.domain}
                            onChange={(e) => setAppForm({ ...appForm, domain: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white" />
                        <input placeholder="Display name (e.g. Slack)" value={appForm.name}
                            onChange={(e) => setAppForm({ ...appForm, name: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white" />
                        <input placeholder="Notes (optional)" value={appForm.notes}
                            onChange={(e) => setAppForm({ ...appForm, notes: e.target.value })}
                            className="px-3 py-2 bg-slate-100 dark:bg-white/5 border border-slate-300 dark:border-white/10 rounded-lg text-sm text-slate-900 dark:text-white sm:col-span-2" />
                        <button onClick={addApp} disabled={saving || !appForm.name || !appForm.domain}
                            className="sm:col-span-2 py-2 rounded-lg bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 disabled:opacity-50 transition-all">
                            {saving ? 'Saving…' : 'Save Known Application'}
                        </button>
                        <p className="sm:col-span-2 text-xs text-slate-500">
                            Matches this domain and its subdomains. Future anomalous traffic to this destination
                            will be suppressed by the detector instead of raised as a Shadow IT alert.
                        </p>
                    </div>
                )}

                {loading ? (
                    <div className="text-center py-8"><Loader2 className="w-5 h-5 animate-spin mx-auto text-purple-400" /></div>
                ) : apps.length === 0 ? (
                    <p className="text-sm text-slate-500 py-4">No known applications yet — add the SaaS tools your organization has approved.</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="border-b border-slate-200 dark:border-white/10">
                                <tr className="text-xs text-slate-900 dark:text-slate-500 font-medium">
                                    <th className="text-left py-2 px-3">Name</th>
                                    <th className="text-left py-2 px-3">Domain</th>
                                    <th className="text-left py-2 px-3">Notes</th>
                                    <th className="text-left py-2 px-3">Added</th>
                                    <th className="py-2 px-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {apps.map((a) => (
                                    <tr key={a.id} className="border-b border-slate-200 dark:border-white/5">
                                        <td className="py-2 px-3 text-xs font-medium text-slate-900 dark:text-white">{a.name}</td>
                                        <td className="py-2 px-3 text-xs font-mono text-slate-700 dark:text-slate-300">{a.domain}</td>
                                        <td className="py-2 px-3 text-xs text-slate-500 max-w-[220px] truncate">{a.notes || '—'}</td>
                                        <td className="py-2 px-3 text-xs text-slate-500">{formatDate(a.created_at)}</td>
                                        <td className="py-2 px-3 text-right">
                                            <button onClick={() => removeApp(a.id)} className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-all">
                                                <Trash2 className="w-3.5 h-3.5" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </GlassCard>
        </div>
    )
}

export default function KnownAssetsPage() {
    return (
        <Suspense fallback={null}>
            <KnownAssetsInner />
        </Suspense>
    )
}
