import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  AddressingReportSchema,
  DeviceConfigSchema,
  Ikev2CertCheckSchema,
  Ikev2RemoteIdSchema,
  PoolBlockSchema,
  SshClientConfigSchema,
  type AddressingReport,
  type DeviceConfig,
  type Ikev2RemoteId,
  type PoolBlock,
  type SshClientConfig,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

const LooseRecordSchema = z.record(z.string(), z.unknown());

export interface VpnInboundRow {
  id: number;
  enable: boolean;
  remark: string;
  port: number;
  protocol: string;
  listen: string;
  settings: Record<string, unknown>;
}

const VpnInboundSchema = z
  .object({
    id: z.number(),
    enable: z.boolean().default(false),
    remark: z.string().default(''),
    port: z.number().default(0),
    protocol: z.string().default(''),
    listen: z.string().default(''),
    settings: LooseRecordSchema.default({}),
  })
  .loose();

async function fetchVpnInbounds(): Promise<VpnInboundRow[]> {
  const msg = await HttpUtil.get('/panel/api/inbounds/list', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch inbounds');
  const validated = parseMsg(msg, z.array(VpnInboundSchema), 'inbounds/list');
  if (!Array.isArray(validated.obj)) return [];
  return validated.obj
    .filter((row) => row.id > 0)
    .map((row) => ({
      id: row.id,
      enable: row.enable,
      remark: row.remark,
      port: row.port,
      protocol: row.protocol,
      listen: row.listen,
      settings: (row.settings ?? {}) as Record<string, unknown>,
    }));
}

export function useVpnInbounds() {
  const query = useQuery({
    queryKey: keys.inbounds.root(),
    queryFn: fetchVpnInbounds,
  });
  return {
    inbounds: query.data ?? [],
    loading: query.isFetching,
    refetch: query.refetch,
    fetched: query.isSuccess,
    fetchError:
      query.error instanceof Error ? query.error.message : query.error ? String(query.error) : null,
  };
}

async function fetchAddressing(inboundId: number): Promise<AddressingReport | null> {
  const msg = await HttpUtil.get(`/panel/api/inbounds/${inboundId}/addressing`, undefined, {
    silent: true,
  });
  if (!msg?.success) return null;
  const validated = parseMsg(msg, AddressingReportSchema, 'inbounds/addressing');
  return validated.obj;
}

async function fetchPools(): Promise<PoolBlock[]> {
  const msg = await HttpUtil.get('/panel/api/inbounds/pools', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch pools');
  const validated = parseMsg(msg, z.array(PoolBlockSchema), 'inbounds/pools');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

type DeviceConfigKind = 'wg-c' | 'awg' | 'gre' | 'ssh';

const DEVICE_CONFIG_PATHS: Record<DeviceConfigKind, string> = {
  'wg-c': 'wgc-configs',
  awg: 'awg-configs',
  gre: 'gre-configs',
  ssh: 'ssh-configs',
};

async function fetchDeviceConfigs(
  inboundId: number,
  kind: DeviceConfigKind,
  email: string,
): Promise<DeviceConfig[] | SshClientConfig[] | null> {
  const path = DEVICE_CONFIG_PATHS[kind];
  const msg = await HttpUtil.get(
    `/panel/api/inbounds/${inboundId}/${path}`,
    { email },
    { silent: true },
  );
  if (!msg?.success) return null;
  const schema = kind === 'ssh' ? z.array(SshClientConfigSchema) : z.array(DeviceConfigSchema);
  const validated = parseMsg(msg, schema, `inbounds/${path}`);
  return Array.isArray(validated.obj) ? validated.obj : null;
}

export function useVpnAddressing(inboundId: number | null) {
  return useQuery({
    queryKey: keys.vpn.protocols.addressing(inboundId ?? 0),
    queryFn: () => fetchAddressing(inboundId as number),
    enabled: inboundId !== null,
  });
}

export function useVpnPools(enabled: boolean) {
  return useQuery({
    queryKey: keys.vpn.protocols.pools(),
    queryFn: fetchPools,
    enabled,
  });
}

export function useVpnDeviceConfigs(
  inboundId: number | null,
  kind: DeviceConfigKind | null,
  email: string,
) {
  return useQuery({
    queryKey: keys.vpn.protocols.deviceConfigs(inboundId ?? 0, kind ?? '', email),
    queryFn: () => fetchDeviceConfigs(inboundId as number, kind as DeviceConfigKind, email),
    enabled: inboundId !== null && kind !== null && email !== '',
  });
}
async function fetchIkev2RemoteId(inboundId: number): Promise<Ikev2RemoteId | null> {
  const msg = await HttpUtil.get(`/panel/api/inbounds/${inboundId}/ikev2-remote-id`, undefined, {
    silent: true,
  });
  if (!msg?.success) return null;
  const validated = parseMsg(msg, Ikev2RemoteIdSchema, 'inbounds/ikev2-remote-id');
  return validated.obj;
}

export function useVpnIkev2RemoteId(inboundId: number | null) {
  return useQuery({
    queryKey: keys.vpn.protocols.ikev2RemoteId(inboundId ?? 0),
    queryFn: () => fetchIkev2RemoteId(inboundId as number),
    enabled: inboundId !== null,
  });
}

const JSON_HEADERS = { headers: { 'Content-Type': 'application/json' } };

export function useVpnProtocolMutations() {
  const queryClient = useQueryClient();
  const invalidateInbounds = () =>
    queryClient.invalidateQueries({ queryKey: keys.inbounds.root() });

  const generateCertMut = useMutation({
    mutationFn: ({ path }: { path: string }) => HttpUtil.post(path, {}, JSON_HEADERS),
  });

  const checkIkev2CertMut = useMutation({
    mutationFn: (settings: Record<string, unknown>) =>
      HttpUtil.post('/panel/api/inbounds/check-ikev2-cert', { settings: JSON.stringify(settings) }),
  });

  const saveInboundMut = useMutation({
    mutationFn: ({ payload }: { payload: Record<string, unknown> }) =>
      HttpUtil.post('/panel/api/inbounds/add', payload, JSON_HEADERS),
    onSuccess: (msg) => {
      if (msg?.success) invalidateInbounds();
    },
  });

  const updateInboundMut = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: Record<string, unknown> }) =>
      HttpUtil.post(`/panel/api/inbounds/update/${id}`, payload, JSON_HEADERS),
    onSuccess: (msg) => {
      if (msg?.success) invalidateInbounds();
    },
  });

  const deleteInboundMut = useMutation({
    mutationFn: (id: number) => HttpUtil.post(`/panel/api/inbounds/del/${id}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidateInbounds();
    },
  });

  const setEnableMut = useMutation({
    mutationFn: ({ id, enable }: { id: number; enable: boolean }) =>
      HttpUtil.post(`/panel/api/inbounds/setEnable/${id}`, { enable }),
    onSuccess: (msg) => {
      if (msg?.success) invalidateInbounds();
    },
  });

  return {
    generateCert: (path: string) => generateCertMut.mutateAsync({ path }),
    checkIkev2Cert: async (settings: Record<string, unknown>) => {
      const msg = await checkIkev2CertMut.mutateAsync(settings);
      if (!msg?.success) return null;
      return parseMsg(msg, Ikev2CertCheckSchema, 'inbounds/check-ikev2-cert').obj;
    },
    saveInbound: (payload: Record<string, unknown>) => saveInboundMut.mutateAsync({ payload }),
    updateInbound: (id: number, payload: Record<string, unknown>) =>
      updateInboundMut.mutateAsync({ id, payload }),
    deleteInbound: (id: number) => deleteInboundMut.mutateAsync(id),
    setEnable: (id: number, enable: boolean) => setEnableMut.mutateAsync({ id, enable }),
  };
}
