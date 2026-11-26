import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  SshOutboundConfigSchema,
  VpnOutKindSchema,
  VpnOutboundConfigSchema,
  type SshOutboundConfig,
  type VpnOutKind,
  type VpnOutboundConfig,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

async function fetchVpnTunnels(): Promise<VpnOutboundConfig[]> {
  const msg = await HttpUtil.post('/panel/api/xray/vpnoutbound/list', {}, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch vpn outbound tunnels');
  const validated = parseMsg(msg, z.array(VpnOutboundConfigSchema), 'xray/vpnoutbound list');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchKinds(): Promise<VpnOutKind[]> {
  const msg = await HttpUtil.post('/panel/api/xray/vpnoutbound/kinds', {}, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch vpn outbound kinds');
  const validated = parseMsg(msg, z.array(VpnOutKindSchema), 'xray/vpnoutbound kinds');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchSshTunnels(): Promise<SshOutboundConfig[]> {
  const msg = await HttpUtil.post('/panel/api/xray/sshoutbound/list', {}, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch ssh outbound tunnels');
  const validated = parseMsg(msg, z.array(SshOutboundConfigSchema), 'xray/sshoutbound list');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

export function useVpnOutboundsQuery() {
  const list = useQuery({
    queryKey: keys.xray.vpnOutbounds.list(),
    queryFn: fetchVpnTunnels,
  });
  const kinds = useQuery({
    queryKey: keys.xray.vpnOutbounds.kinds(),
    queryFn: fetchKinds,
    staleTime: Infinity,
  });
  return {
    tunnels: list.data ?? [],
    kinds: kinds.data ?? [],
    loading: list.isFetching,
    refetch: list.refetch,
  };
}

export function useSshOutboundsQuery() {
  const list = useQuery({
    queryKey: keys.xray.vpnOutbounds.sshList(),
    queryFn: fetchSshTunnels,
  });
  return { tunnels: list.data ?? [], loading: list.isFetching, refetch: list.refetch };
}

export interface VpnTunnelFormValues {
  tag: string;
  kind: string;
  remark: string;
  enable: boolean;
  via: string;
  settings: string;
}

export interface SshTunnelFormValues {
  tag: string;
  remark: string;
  address: string;
  port: number;
  username: string;
  authType: 'password' | 'privateKey';
  password: string;
  privateKey: string;
  passphrase: string;
  knownHost: string;
}

export function useVpnOutboundMutations() {
  const queryClient = useQueryClient();
  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: keys.xray.vpnOutbounds.root() });

  const saveMut = useMutation({
    mutationFn: (values: VpnTunnelFormValues) =>
      HttpUtil.post('/panel/api/xray/vpnoutbound/save', values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const delMut = useMutation({
    mutationFn: (tag: string) =>
      HttpUtil.post('/panel/api/xray/vpnoutbound/delete', { tag }),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const statusMut = useMutation({
    mutationFn: (tag: string) =>
      HttpUtil.post('/panel/api/xray/vpnoutbound/status', { tag }, { silent: true }),
  });

  const status = async (tag: string): Promise<{ running: boolean; detail: string } | null> => {
    const msg = await statusMut.mutateAsync(tag);
    if (!msg?.success) return null;
    const validated = parseMsg(
      msg,
      z.object({ running: z.boolean().default(false), detail: z.string().default('') }).loose(),
      'xray/vpnoutbound status',
    );
    return validated.obj;
  };

  return {
    save: (values: VpnTunnelFormValues) => saveMut.mutateAsync(values),
    remove: (tag: string) => delMut.mutateAsync(tag),
    status,
  };
}

export function useSshOutboundMutations() {
  const queryClient = useQueryClient();
  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: keys.xray.vpnOutbounds.sshList() });

  const saveMut = useMutation({
    mutationFn: (values: SshTunnelFormValues) =>
      HttpUtil.post('/panel/api/xray/sshoutbound/save', values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const delMut = useMutation({
    mutationFn: (tag: string) =>
      HttpUtil.post('/panel/api/xray/sshoutbound/delete', { tag }),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const statusMut = useMutation({
    mutationFn: (tag: string) =>
      HttpUtil.post('/panel/api/xray/sshoutbound/status', { tag }, { silent: true }),
  });

  const status = async (tag: string): Promise<{ running: boolean; log: string } | null> => {
    const msg = await statusMut.mutateAsync(tag);
    if (!msg?.success) return null;
    const validated = parseMsg(
      msg,
      z.object({ running: z.boolean().default(false), log: z.string().default('') }).loose(),
      'xray/sshoutbound status',
    );
    return validated.obj;
  };

  return {
    save: (values: SshTunnelFormValues) => saveMut.mutateAsync(values),
    remove: (tag: string) => delMut.mutateAsync(tag),
    status,
  };
}
