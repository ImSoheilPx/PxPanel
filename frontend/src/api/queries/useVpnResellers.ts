import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  InboundBriefSchema,
  ResellerViewSchema,
  type InboundBrief,
  type ResellerView,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

async function fetchResellers(): Promise<ResellerView[]> {
  const msg = await HttpUtil.get('/panel/api/resellers/list', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch resellers');
  const validated = parseMsg(msg, z.array(ResellerViewSchema), 'resellers/list');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchAssignableInbounds(): Promise<InboundBrief[]> {
  const msg = await HttpUtil.get('/panel/api/resellers/inbounds', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch inbounds');
  const validated = parseMsg(msg, z.array(InboundBriefSchema), 'resellers/inbounds');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

export function useVpnResellersQuery() {
  const query = useQuery({ queryKey: keys.vpn.resellers.list(), queryFn: fetchResellers });
  return {
    resellers: query.data ?? [],
    loading: query.isFetching,
    refetch: query.refetch,
    fetched: query.isSuccess,
    fetchError:
      query.error instanceof Error ? query.error.message : query.error ? String(query.error) : null,
  };
}

export function useVpnResellerInboundsQuery() {
  const query = useQuery({
    queryKey: keys.vpn.resellers.inbounds(),
    queryFn: fetchAssignableInbounds,
    staleTime: 30_000,
  });
  return query.data ?? [];
}

export interface ResellerFormValues {
  username: string;
  password: string;
  nickname: string;
  enable: boolean;
  unlimited: boolean;
  allowanceGb: number;
  daysPerGb: number;
  minCreateGb: number;
  minAddGb: number;
  allowExternalProxy: boolean;
  allowOverview: boolean;
  allowOverviewManage: boolean;
  inboundIds: number[];
}

export function useVpnResellerMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: keys.vpn.resellers.root() });

  const addMut = useMutation({
    mutationFn: (values: ResellerFormValues) => HttpUtil.post('/panel/api/resellers/add', values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, values }: { id: number; values: ResellerFormValues }) =>
      HttpUtil.post(`/panel/api/resellers/update/${id}`, values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const delMut = useMutation({
    mutationFn: ({ id, mode }: { id: number; mode: 'keep' | 'cascade' }) =>
      HttpUtil.post(`/panel/api/resellers/del/${id}`, { mode }),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const rechargeMut = useMutation({
    mutationFn: ({ id, gb }: { id: number; gb: number }) =>
      HttpUtil.post(`/panel/api/resellers/recharge/${id}`, { gb }),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  return {
    add: (values: ResellerFormValues) => addMut.mutateAsync(values),
    update: (id: number, values: ResellerFormValues) => updateMut.mutateAsync({ id, values }),
    remove: (id: number, mode: 'keep' | 'cascade') => delMut.mutateAsync({ id, mode }),
    recharge: (id: number, gb: number) => rechargeMut.mutateAsync({ id, gb }),
  };
}
