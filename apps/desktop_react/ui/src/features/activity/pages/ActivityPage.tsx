import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { listRecentEvents, getEventDetail, ftsSearch } from "@/lib/tauri";
import { usePollInterval } from "@/stores/themeStore";
import { useTranslation } from "react-i18next";

const EVENT_TYPES = [
  { value: "", label: "common.allTypes" },
  { value: "session_started", label: "activity.session" },
  { value: "tool_call", label: "activity.toolCall" },
  { value: "approval_created", label: "activity.approval" },
  { value: "approval_resolved", label: "activity.resolved" },
  { value: "redaction_scan", label: "activity.redaction" },
];

const TIME_RANGES = [
  { value: "1h", label: "timeRange.1h", seconds: 3600 },
  { value: "24h", label: "timeRange.24h", seconds: 86400 },
  { value: "7d", label: "timeRange.7d", seconds: 604800 },
  { value: "30d", label: "timeRange.30d", seconds: 2592000 },
  { value: "all", label: "timeRange.all", seconds: 0 },
];

export function ActivityPage() {
  const [search, setSearch] = useState("");
  const [eventType, setEventType] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);

  const { t } = useTranslation();

  const eventTypeFilter = useMemo(
    () => (eventType ? [eventType] : null),
    [eventType]
  );

  const pollMs = usePollInterval();
  const { data: events } = useQuery({
    queryKey: ["recentEvents", eventTypeFilter],
    queryFn: () =>
      listRecentEvents({
        limit: 100,
        event_type_filter: eventTypeFilter,
      }),
    refetchInterval: pollMs,
  });

  const { data: searchedEvents } = useQuery({
    queryKey: ["ftsSearch", search],
    queryFn: () => ftsSearch({ query: search, limit: 20 }),
    enabled: search.trim().length > 0,
  });

  const { data: detail } = useQuery({
    queryKey: ["eventDetail", selectedEventId],
    queryFn: () => getEventDetail({ event_id: selectedEventId! }),
    enabled: selectedEventId !== null,
  });

  const filteredEvents = useMemo(() => {
    const source = search.trim() ? searchedEvents : events;
    if (!source) return undefined;
    const range = TIME_RANGES.find((r) => r.value === timeRange);
    if (!range || range.seconds === 0) return source;
    const cutoff = Math.floor(Date.now() / 1000) - range.seconds;
    return source.filter((e) => e.created_at >= cutoff);
  }, [events, searchedEvents, search, timeRange]);

  return (
    <div className="grid h-full grid-cols-1 gap-6 lg:grid-cols-5 animate-fade-in-up">
      <div className="vigil-card p-5 lg:col-span-3">
        <div className="flex items-center gap-3">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("activity.searchPlaceholder")}
            className="vigil-input flex-1"
          />
          <select
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            className="vigil-input"
          >
            {EVENT_TYPES.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(opt.label)}
              </option>
            ))}
          </select>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="vigil-input"
          >
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {t(r.label)}
              </option>
            ))}
          </select>
        </div>
        <table className="mt-4 w-full">
          <thead>
            <tr>
              {[t("activity.time"), t("protection.type"), t("activity.session"), t("protection.summary")].map((h) => (
                <th key={h} className="vigil-table-header pb-2 text-left">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-vigils-bg-surface">
            {filteredEvents?.map((e) => (
              <tr
                key={e.event_id}
                onClick={() => setSelectedEventId(e.event_id)}
                className={`cursor-pointer ${
                  selectedEventId === e.event_id ? "bg-vigils-bg-tertiary/50" : ""
                }`}
              >
                <td className="vigil-table-cell">
                  {new Date(e.created_at * 1000).toLocaleTimeString()}
                </td>
                <td className="vigil-table-cell">{e.event_type}</td>
                <td className="vigil-table-cell text-vigils-cyan">
                  {e.session_id}
                </td>
                <td className="vigil-table-cell text-vigils-text-primary">
                  {e.redacted_text ?? "-"}
                </td>
              </tr>
            )) ?? (
              <tr>
                <td
                  colSpan={4}
                  className="py-6 text-center text-sm text-vigils-text-muted"
                >
                  {t("activity.noEvents")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="vigil-card p-5 lg:col-span-2">
        <h3 className="text-sm font-bold text-vigils-text-primary">{t("activity.eventDetail")}</h3>
        {detail ? (
          <div className="mt-4 space-y-3">
            <div className="font-mono text-xs text-vigils-text-muted">
              {t("activity.eventId")}: {detail.event_id}
            </div>
            <div className="text-sm text-vigils-text-secondary">
              {t("activity.type")}: {detail.event_type}
            </div>
            <div className="text-sm text-vigils-text-secondary">
              {t("activity.session")}: {detail.session_id}
            </div>
            <div className="text-sm text-vigils-text-secondary">
              {t("activity.hash")}: {detail.event_hash.slice(0, 16)}...
            </div>
            <pre className="max-h-[400px] overflow-auto rounded-md bg-vigils-bg-deep p-3 text-xs text-vigils-text-secondary">
              {JSON.stringify(detail.payload, null, 2)}
            </pre>
          </div>
        ) : (
          <div className="mt-8 text-center text-sm text-vigils-text-muted">
            {t("activity.selectEvent")}
          </div>
        )}
      </div>
    </div>
  );
}
