import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  CoreCatalogSchema,
  CoreConfigEnvelopeSchema,
  CoreConfigSaveResultSchema,
  CoreStatusEnvelopeSchema,
  ProvisionStateSchema,
  UninstallStateSchema,
  type CoreCatalog,
  type CoreConfigEnvelope,
  type CoreConfigSaveResult,
  type CoreStatusEnvelope,
  type ProvisionState,
  type UninstallState,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

async function fetchStatus(): Promise<CoreStatusEnvelope | null> {
  const msg = await HttpUtil.get('/panel/api/core/status', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch core status');
  const validated = parseMsg(msg, CoreStatusEnvelopeSchema, 'core/status');
  return validated.obj;
}

async function fetchCatalog(): Promise<CoreCatalog | null> {
  const msg = await HttpUtil.get('/panel/api/core/catalog', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch core catalog');
  const validated = parseMsg(msg, CoreCatalogSchema, 'core/catalog');
  return validated.obj;
}

async function fetchProvisionStatus(): Promise<ProvisionState | null> {
  const msg = await HttpUtil.get('/panel/api/core/provision-status', undefined, { silent: true });
  if (!msg?.success) return null;
  const validated = parseMsg(msg, ProvisionStateSchema, 'core/provision-status');
  return validated.obj;
}

async function fetchUninstallStatus(): Promise<UninstallState | null> {
  const msg = await HttpUtil.get('/panel/api/core/uninstall-status', undefined, { silent: true });
  if (!msg?.success) return null;
  const validated = parseMsg(msg, UninstallStateSchema, 'core/uninstall-status');
  return validated.obj;
}

async function fetchLogs(core: string): Promise<string> {
  const msg = await HttpUtil.get(`/panel/api/core/logs/${encodeURIComponent(core)}`, undefined, {
    silent: true,
  });
  if (!msg?.success) return '';
  return typeof msg.obj === 'string' ? msg.obj : '';
}

async function fetchCoreConfig(core: string): Promise<CoreConfigEnvelope | null> {
  const msg = await HttpUtil.get(`/panel/api/core/config/${encodeURIComponent(core)}`, undefined, {
    silent: true,
  });
  if (!msg?.success) return null;
  const validated = parseMsg(msg, CoreConfigEnvelopeSchema, 'core/config');
  return validated.obj;
}

export function useVpnCoreStatus(pollMs = 0) {
  const query = useQuery({
    queryKey: keys.vpn.core.status(),
    queryFn: fetchStatus,
    refetchInterval: pollMs > 0 ? pollMs : false,
  });
  return { status: query.data ?? null, loading: query.isFetching, refetch: query.refetch };
}

export function useVpnCoreCatalog() {
  const query = useQuery({ queryKey: keys.vpn.core.catalog(), queryFn: fetchCatalog });
  return query.data;
}

export function useVpnProvisionStatus(polling: boolean) {
  return useQuery({
    queryKey: keys.vpn.core.provision(),
    queryFn: fetchProvisionStatus,
    enabled: polling,
    refetchInterval: polling ? 1500 : false,
  });
}

export function useVpnUninstallStatus(polling: boolean) {
  return useQuery({
    queryKey: keys.vpn.core.uninstall(),
    queryFn: fetchUninstallStatus,
    enabled: polling,
    refetchInterval: polling ? 1500 : false,
  });
}

export function useVpnCoreLogs(core: string | null) {
  return useQuery({
    queryKey: keys.vpn.core.logs(core ?? ''),
    queryFn: () => fetchLogs(core as string),
    enabled: core !== null,
  });
}

export function useVpnCoreConfig(core: string | null) {
  return useQuery({
    queryKey: keys.vpn.core.config(core ?? ''),
    queryFn: () => fetchCoreConfig(core as string),
    enabled: core !== null,
  });
}

export function useVpnCoreMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: keys.vpn.core.root() });

  const provisionMut = useMutation({
    mutationFn: (cores: string[]) =>
      HttpUtil.post('/panel/api/core/provision', { cores: cores.join(',') }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.vpn.core.provision() });
    },
  });

  const uninstallMut = useMutation({
    mutationFn: ({ cores, inbounds }: { cores: string[]; inbounds: 'delete' | 'keep' }) =>
      HttpUtil.post('/panel/api/core/uninstall', {
        cores: cores.join(','),
        inbounds,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.vpn.core.uninstall() });
    },
  });

  const restartMut = useMutation({
    mutationFn: (core: string) =>
      HttpUtil.post(`/panel/api/core/restart/${encodeURIComponent(core)}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const restartAllMut = useMutation({
    mutationFn: () => HttpUtil.post('/panel/api/core/restart-all'),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const stopMut = useMutation({
    mutationFn: (core: string) => HttpUtil.post(`/panel/api/core/stop/${encodeURIComponent(core)}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const rebootMut = useMutation({
    mutationFn: () => HttpUtil.post('/panel/api/core/reboot'),
  });

  const saveConfigMut = useMutation({
    mutationFn: (payload: { core: string; inboundId: number; file: string; text: string }) =>
      HttpUtil.post(`/panel/api/core/config/${encodeURIComponent(payload.core)}`, {
        inboundId: payload.inboundId,
        file: payload.file,
        mode: 'replace',
        text: payload.text,
      }),
    onSuccess: () => {
      invalidate();
    },
  });

  const startProvision = async (cores: string[]): Promise<ProvisionState | null> => {
    const msg = await provisionMut.mutateAsync(cores);
    if (!msg?.success) return null;
    const validated = parseMsg(msg, ProvisionStateSchema, 'core/provision');
    return validated.obj;
  };

  const startUninstall = async (
    cores: string[],
    inbounds: 'delete' | 'keep',
  ): Promise<UninstallState | null> => {
    const msg = await uninstallMut.mutateAsync({ cores, inbounds });
    if (!msg?.success) return null;
    const validated = parseMsg(msg, UninstallStateSchema, 'core/uninstall');
    return validated.obj;
  };

  const saveConfig = async (
    core: string,
    inboundId: number,
    file: string,
    text: string,
  ): Promise<CoreConfigSaveResult | null> => {
    const msg = await saveConfigMut.mutateAsync({ core, inboundId, file, text });
    if (!msg?.success) return null;
    const validated = parseMsg(msg, CoreConfigSaveResultSchema, 'core/config save');
    return validated.obj;
  };

  return {
    startProvision,
    startUninstall,
    restart: (core: string) => restartMut.mutateAsync(core),
    restartAll: () => restartAllMut.mutateAsync(),
    stop: (core: string) => stopMut.mutateAsync(core),
    reboot: () => rebootMut.mutateAsync(),
    saveConfig,
  };
}
