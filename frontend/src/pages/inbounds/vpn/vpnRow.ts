import { coerceInboundJsonField } from '@/models/dbinbound';
import type { VpnInboundRow } from '@/api/queries/useVpnProtocols';

// Structural source: both the slim/full DBInbound instances (edit + info
// flows, which hydrate first) and the list's DBInboundRecord projection
// satisfy it.
export interface VpnRowSource {
  id: number;
  enable?: boolean;
  remark: string;
  port: number;
  protocol: string;
  listen?: string;
  settings: unknown;
}

// The vpn accounts/tools panels take the VpnInboundRow shape the old
// vpn-protocols page fetched; adapt a row of the unified inbounds list to it.
export function vpnRowFromRecord(record: VpnRowSource): VpnInboundRow {
  return {
    id: record.id,
    enable: record.enable ?? true,
    remark: record.remark,
    port: record.port,
    protocol: record.protocol,
    listen: typeof record.listen === 'string' ? record.listen : '',
    settings: (coerceInboundJsonField(record.settings) ?? {}) as Record<string, unknown>,
  };
}
