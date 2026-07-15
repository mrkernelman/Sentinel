import { resolveService } from '@/lib/services'

/** Renders the service/vendor resolved from a detection's destination
 *  (e.g. "Google Drive"), styled distinctly from an unrecognized best-effort
 *  guess or the no-hostname "Unknown" case. */
export default function ServiceBadge({ dst }: { dst: string | null | undefined }) {
    const service = resolveService(dst)
    if (!service || service.name === 'Unknown') {
        return <span className="text-xs text-slate-400 dark:text-slate-600">Unknown</span>
    }
    if (!service.recognized) {
        return <span className="text-xs text-slate-500 dark:text-slate-400">{service.name}</span>
    }
    return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-sky-500/12 text-sky-500 dark:text-sky-400 border border-sky-500/25">
            {service.name}
        </span>
    )
}
