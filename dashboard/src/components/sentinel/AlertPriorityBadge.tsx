import type { AlertPriority } from "@/types/sentinel";

const BADGE_STYLES: Record<AlertPriority, string> = {
  Critical:
    "bg-sentinel-critical/10 text-sentinel-critical border border-sentinel-critical/20",
  High: "bg-sentinel-high/10 text-sentinel-high border border-sentinel-high/20",
  Medium:
    "bg-sentinel-medium/10 text-sentinel-medium border border-sentinel-medium/20",
};

interface Props {
  readonly priority: AlertPriority;
}

export function AlertPriorityBadge({ priority }: Props) {
  return (
    <span
      className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${BADGE_STYLES[priority]}`}
    >
      {priority}
    </span>
  );
}
