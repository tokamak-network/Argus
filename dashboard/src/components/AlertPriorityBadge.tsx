import type { AlertPriority } from "@/types/sentinel";

const BADGE_STYLES: Record<AlertPriority, string> = {
  Medium: "bg-tokamak-yellow/20 text-tokamak-yellow",
  High: "bg-orange-500/20 text-orange-400",
  Critical: "bg-tokamak-red/20 text-tokamak-red",
};

interface Props {
  readonly priority: AlertPriority;
}

export function AlertPriorityBadge({ priority }: Props) {
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${BADGE_STYLES[priority]}`}
    >
      {priority}
    </span>
  );
}
