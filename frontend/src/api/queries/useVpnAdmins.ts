import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  AdminRowSchema,
  InboundBriefSchema,
  PermissionSlugSchema,
  type AdminRow,
  type InboundBrief,
  type PermissionSlug,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

async function fetchAdmins(): Promise<AdminRow[]> {
  const msg = await HttpUtil.get('/panel/api/admins/list', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch admins');
  const validated = parseMsg(msg, z.array(AdminRowSchema), 'admins/list');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchPermissions(): Promise<PermissionSlug[]> {
  const msg = await HttpUtil.get('/panel/api/admins/permissions', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch permissions');
  const validated = parseMsg(msg, z.array(PermissionSlugSchema), 'admins/permissions');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchAdminInbounds(): Promise<InboundBrief[]> {
  const msg = await HttpUtil.get('/panel/api/admins/inbounds', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch inbounds');
  const validated = parseMsg(msg, z.array(InboundBriefSchema), 'admins/inbounds');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

export function useVpnAdminsQuery() {
  const query = useQuery({ queryKey: keys.vpn.admins.list(), queryFn: fetchAdmins });
  return {
    admins: query.data ?? [],
    loading: query.isFetching,
    refetch: query.refetch,
    fetched: query.isSuccess,
    fetchError:
      query.error instanceof Error ? query.error.message : query.error ? String(query.error) : null,
  };
}

export function useVpnPermissionsQuery() {
  const query = useQuery({
    queryKey: keys.vpn.admins.permissions(),
    queryFn: fetchPermissions,
    staleTime: Infinity,
  });
  return query.data ?? [];
}

export function useVpnAdminInboundsQuery() {
  const query = useQuery({
    queryKey: keys.vpn.admins.inbounds(),
    queryFn: fetchAdminInbounds,
    staleTime: 30_000,
  });
  return query.data ?? [];
}

export interface AdminFormValues {
  username: string;
  password: string;
  nickname: string;
  enable: boolean;
  isSuperAdmin: boolean;
  permissions: string[];
  inboundIds: number[];
}

export function useVpnAdminMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: keys.vpn.admins.root() });

  const addMut = useMutation({
    // Arrays travel as repeated form keys, which the default encoder emits.
    mutationFn: (values: AdminFormValues) => HttpUtil.post('/panel/api/admins/add', values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, values }: { id: number; values: AdminFormValues }) =>
      HttpUtil.post(`/panel/api/admins/update/${id}`, values),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const delMut = useMutation({
    mutationFn: (id: number) => HttpUtil.post(`/panel/api/admins/del/${id}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const reassignMut = useMutation({
    mutationFn: ({ from, to }: { from: number; to: number }) =>
      HttpUtil.post(`/panel/api/admins/reassign/${from}/${to}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidate();
    },
  });

  const reassign = async (from: number, to: number): Promise<number | null> => {
    const msg = await reassignMut.mutateAsync({ from, to });
    if (!msg?.success) return null;
    const validated = parseMsg(
      msg,
      z.object({ moved: z.number().default(0) }).loose(),
      'admins/reassign',
    );
    return validated.obj?.moved ?? null;
  };

  return {
    add: (values: AdminFormValues) => addMut.mutateAsync(values),
    update: (id: number, values: AdminFormValues) => updateMut.mutateAsync({ id, values }),
    remove: (id: number) => delMut.mutateAsync(id),
    reassign,
  };
}
