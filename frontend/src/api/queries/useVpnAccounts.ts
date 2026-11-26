import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { HttpUtil } from '@/utils';
import { parseMsg } from '@/utils/zodValidate';
import {
  AccountListSchema,
  AccountMembershipSchema,
  BulkMembershipResultSchema,
  BulkPreviewSchema,
  ResellerBalanceSchema,
  type AccountList,
  type AccountMembership,
  type BulkMembershipResult,
  type BulkPreview,
  type ResellerBalance,
} from '@/schemas/api/vpn';
import { keys } from '@/api/queryKeys';

const JSON_HEADERS = { headers: { 'Content-Type': 'application/json' } };

export interface AccountListParams {
  page: number;
  size: number;
  search?: string;
}

async function fetchAccounts(params: AccountListParams): Promise<AccountList> {
  const msg = await HttpUtil.get('/panel/api/accounts/list', params, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch accounts');
  const validated = parseMsg(msg, AccountListSchema, 'accounts/list');
  return validated.obj ?? { rows: [], total: 0, page: 1, size: params.size, sort: '' };
}

async function fetchAssignable(): Promise<AccountMembership[]> {
  const msg = await HttpUtil.get('/panel/api/accounts/assignable', undefined, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch assignable inbounds');
  const validated = parseMsg(msg, z.array(AccountMembershipSchema), 'accounts/assignable');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

async function fetchBalance(): Promise<ResellerBalance> {
  const msg = await HttpUtil.get('/panel/api/inbounds/resellerBalance', undefined, {
    silent: true,
  });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch balance');
  const validated = parseMsg(msg, ResellerBalanceSchema, 'inbounds/resellerBalance');
  return (
    validated.obj ?? { isReseller: false, allowanceBytes: 0, spentBytes: 0, availableBytes: 0 }
  );
}

async function fetchOnline(): Promise<string[]> {
  const msg = await HttpUtil.post('/panel/api/inbounds/onlineMemberships', {}, { silent: true });
  if (!msg?.success) throw new Error(msg?.msg || 'Failed to fetch online memberships');
  const validated = parseMsg(msg, z.array(z.string()), 'inbounds/onlineMemberships');
  return Array.isArray(validated.obj) ? validated.obj : [];
}

export function useVpnAccounts(params: AccountListParams) {
  const query = useQuery({
    queryKey: keys.vpn.accounts.list(params),
    queryFn: () => fetchAccounts(params),
  });
  return { data: query.data, loading: query.isFetching, refetch: query.refetch };
}

export function useVpnAssignableInbounds() {
  const query = useQuery({
    queryKey: keys.vpn.accounts.assignable(),
    queryFn: fetchAssignable,
    staleTime: 30_000,
  });
  return query.data ?? [];
}

export function useVpnResellerBalance() {
  const query = useQuery({
    queryKey: keys.vpn.accounts.balance(),
    queryFn: fetchBalance,
    staleTime: 10_000,
  });
  return query.data;
}

export function useVpnOnlineMemberships(enabled: boolean) {
  const query = useQuery({
    queryKey: keys.vpn.accounts.online(),
    queryFn: fetchOnline,
    enabled,
    refetchInterval: 15_000,
  });
  return query.data ?? [];
}

export interface BulkMembershipRequest {
  op: 'addInbounds' | 'removeInbounds';
  inboundIds: number[];
  targets: { inboundId: number; email: string }[];
}

export function useVpnAccountMutations() {
  const queryClient = useQueryClient();
  const invalidateAccounts = () =>
    queryClient.invalidateQueries({ queryKey: keys.vpn.accounts.root() });

  const setMembershipEnableMut = useMutation({
    mutationFn: ({
      inboundId,
      email,
      enable,
    }: {
      inboundId: number;
      email: string;
      enable: boolean;
    }) =>
      HttpUtil.post(
        `/panel/api/inbounds/${inboundId}/setMembershipEnable/${encodeURIComponent(email)}`,
        { enable },
      ),
    onSuccess: (msg) => {
      if (msg?.success) invalidateAccounts();
    },
  });

  const bulkPreviewMut = useMutation({
    mutationFn: (request: BulkMembershipRequest) =>
      HttpUtil.post(
        '/panel/api/inbounds/bulkPreview',
        { data: JSON.stringify(request) },
        JSON_HEADERS,
      ),
  });

  const bulkMembershipMut = useMutation({
    mutationFn: (request: BulkMembershipRequest) =>
      HttpUtil.post(
        '/panel/api/inbounds/bulkMembership',
        { data: JSON.stringify(request) },
        JSON_HEADERS,
      ),
    onSuccess: (msg) => {
      if (msg?.success) invalidateAccounts();
    },
  });

  const delAccountMut = useMutation({
    mutationFn: (email: string) =>
      HttpUtil.post(`/panel/api/inbounds/delAccount/${encodeURIComponent(email)}`),
    onSuccess: (msg) => {
      if (msg?.success) invalidateAccounts();
    },
  });

  const runPreview = async (request: BulkMembershipRequest): Promise<BulkPreview | null> => {
    const msg = await bulkPreviewMut.mutateAsync(request);
    if (!msg?.success) return null;
    const validated = parseMsg(msg, BulkPreviewSchema, 'inbounds/bulkPreview');
    return validated.obj;
  };

  const runBulk = async (request: BulkMembershipRequest): Promise<BulkMembershipResult | null> => {
    const msg = await bulkMembershipMut.mutateAsync(request);
    if (!msg?.success) return null;
    const validated = parseMsg(msg, BulkMembershipResultSchema, 'inbounds/bulkMembership');
    return validated.obj;
  };

  return {
    setMembershipEnable: (inboundId: number, email: string, enable: boolean) =>
      setMembershipEnableMut.mutateAsync({ inboundId, email, enable }),
    previewBulk: runPreview,
    applyBulk: runBulk,
    delAccount: (email: string) => delAccountMut.mutateAsync(email),
  };
}
