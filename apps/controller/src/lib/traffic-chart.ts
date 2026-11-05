export interface TrafficSample {
  at: string;
  sentBytes: string;
  receivedBytes: string;
}

// Signed coordinates are rendering-only. Contracts and tooltips keep positive counters.
export function trafficPlot(timeline: TrafficSample[]) {
  const received = timeline.map((item) => [
    Date.parse(item.at),
    -Number(item.receivedBytes),
  ]);

  const sent = timeline.map((item) => [
    Date.parse(item.at),
    Number(item.sentBytes),
  ]);

  const peak = timeline.reduce(
    (value, item) =>
      Math.max(value, Number(item.receivedBytes), Number(item.sentBytes)),
    0,
  );

  return { received, sent, peak };
}
