import { XMLParser, XMLValidator } from "fast-xml-parser";
import { flowSchema } from "@traffic-policy/contracts";
import type { Flow } from "@traffic-policy/contracts";

interface ConntrackMeta {
  "@direction": string;
  layer3?: { src: string; dst: string };
  layer4?: {
    "@protonum": string;
    sport?: string;
    dport?: string;
    type?: string;
    code?: string;
  };
  counters?: { packets: string; bytes: string };
  id?: string;
}

export interface ConnectionSnapshot {
  id: string;
  flow: Flow;
  sentBytes: string | null;
  receivedBytes: string | null;
}

export function parseConnections(xml: string): ConnectionSnapshot[] {
  if (Buffer.byteLength(xml) > 8 * 1024 * 1024)
    throw new Error("Connection snapshot exceeds its limit");

  const document = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@",
    parseTagValue: false,
    processEntities: false,
    isArray: (name) => name === "flow" || name === "meta",
  }).parse(xml);

  if (document.conntrack === undefined)
    throw new Error("Connection snapshot is not a conntrack document");

  if (document.conntrack === "") {
    if (XMLValidator.validate(xml) !== true)
      throw new Error("Connection snapshot ended before its complete document");

    return [];
  }

  const flows = document.conntrack.flow ?? [];

  if (!Array.isArray(flows) || flows.length > 100000)
    throw new Error("Connection snapshot has too many records");

  return flows.map((item: { meta: ConntrackMeta[] }) => {
    const original = item.meta.find(
      (meta) => meta["@direction"] === "original",
    );

    const reply = item.meta.find((meta) => meta["@direction"] === "reply");

    const independent = item.meta.find(
      (meta) => meta["@direction"] === "independent",
    );

    if (
      !original?.layer3 ||
      !original.layer4 ||
      !reply?.layer3 ||
      !reply.layer4 ||
      !independent?.id
    ) {
      throw new Error("Connection snapshot lacks required tuple identity");
    }

    const protocol = Number(original.layer4["@protonum"]);
    const hasPorts = [6, 17, 33, 132].includes(protocol);

    const flow = flowSchema.parse({
      initiatorIp: original.layer3.src,
      responderIp: reply.layer3.src,
      originalDestinationIp: original.layer3.dst,
      protocol,
      originalServicePort: hasPorts ? Number(original.layer4.dport) : null,
      responderServicePort: hasPorts ? Number(reply.layer4.sport) : null,
      icmpType:
        [1, 58].includes(protocol) && original.layer4.type !== undefined
          ? Number(original.layer4.type)
          : null,
      icmpCode:
        [1, 58].includes(protocol) && original.layer4.code !== undefined
          ? Number(original.layer4.code)
          : null,
    });

    const counter = (meta: ConntrackMeta) => {
      if (!meta.counters) return null;

      if (!/^[0-9]+$/.test(meta.counters.bytes))
        throw new Error("Connection byte counter is invalid");

      return meta.counters.bytes;
    };

    return {
      id: [
        independent.id,
        flow.initiatorIp,
        original.layer4.sport ?? "",
        flow.responderIp,
        reply.layer4.dport ?? "",
      ].join("|"),
      flow,
      sentBytes: counter(original),
      receivedBytes: counter(reply),
    };
  });
}
