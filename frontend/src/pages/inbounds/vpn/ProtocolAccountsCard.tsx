import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Card, Input, Modal, Space, Switch, Table, Tag, message } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import type { AccountRow, DeviceConfig, SshClientConfig } from '@/schemas/api/vpn';
import {
  useVpnAccounts,
  useVpnAccountMutations,
  useVpnOnlineMemberships,
} from '@/api/queries/useVpnAccounts';
import { useVpnDeviceConfigs } from '@/api/queries/useVpnProtocols';
import type { VpnInboundRow } from '@/api/queries/useVpnProtocols';
import { downloadText } from '@/lib/download';

type DeviceConfigEntry = DeviceConfig | SshClientConfig;

const deviceConfigText = (entry: DeviceConfigEntry): string => {
  const wgConfig = (entry as DeviceConfig).config;
  if (wgConfig) return wgConfig;
  const ssh = entry as SshClientConfig;
  return `${ssh.plain}\n${ssh.link}`;
};

interface Props {
  inbound: VpnInboundRow;
  onClose: () => void;
}

// The per-inbound account panel: one page of the account read model scoped to
// this inbound's memberships, with the enable/disable switch and the per-account
// device/config viewers of the protocols that mint them.
export default function ProtocolAccountsCard({ inbound, onClose }: Props) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const { data, loading, refetch } = useVpnAccounts({
    page,
    size: pageSize,
    search: search || undefined,
  });
  const { setMembershipEnable } = useVpnAccountMutations();
  const online = useVpnOnlineMemberships(true);

  const rowsOnThisInbound = useMemo(
    () =>
      (data?.rows ?? []).filter((row) =>
        row.memberships.some((membership) => membership.inboundId === inbound.id),
      ),
    [data, inbound.id],
  );

  const onlineSet = useMemo(
    () => new Set(online.filter((pair) => pair.startsWith(`${inbound.id}:`))),
    [online, inbound.id],
  );

  const onToggleMembership = useCallback(
    async (row: AccountRow, enable: boolean) => {
      const msg = await setMembershipEnable(inbound.id, row.email, enable);
      if (msg?.success) messageApi.success(t('pages.vpnProtocols.toasts.membershipUpdated'));
      else messageApi.error(msg?.msg || t('somethingWentWrong'));
    },
    [inbound.id, setMembershipEnable, messageApi, t],
  );

  const columns: ColumnsType<AccountRow> = [
    {
      title: t('pages.vpnProtocols.email'),
      dataIndex: 'email',
      render: (_, row) => (
        <Space>
          <span>{row.email}</span>
          {onlineSet.has(`${inbound.id}:${row.email}`) && <Tag color="green">{t('online')}</Tag>}
        </Space>
      ),
    },
    {
      title: t('pages.vpnProtocols.slot'),
      render: (_, row) => {
        const membership = row.memberships.find((m) => m.inboundId === inbound.id);
        return membership?.slot ?? '—';
      },
    },
    {
      title: t('usage'),
      render: (_, row) => {
        const mb = (row.up + row.down) / (1024 * 1024);
        return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(1)} MB`;
      },
    },
    {
      title: t('enable'),
      render: (_, row) => {
        const membership = row.memberships.find((m) => m.inboundId === inbound.id);
        return (
          <Switch
            aria-label={`${t('enable')} — ${row.email}`}
            checked={membership?.enable ?? false}
            onChange={(next) => onToggleMembership(row, next)}
          />
        );
      },
    },
    {
      title: t('pages.vpnProtocols.configs'),
      render: (_, row) => <DeviceConfigButton inbound={inbound} email={row.email} />,
    },
  ];

  return (
    <Card
      size="small"
      title={
        <Space wrap>
          <span>
            {t('pages.vpnProtocols.accountsTitle', { name: inbound.remark || `#${inbound.id}` })}
          </span>
          <Tag>{t('pages.vpnProtocols.accountsOnline', { count: onlineSet.size })}</Tag>
        </Space>
      }
      extra={
        <Space>
          <Input.Search
            allowClear
            aria-label={t('search')}
            placeholder={t('search') || 'Search'}
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            style={{ width: 200 }}
          />
          <Button onClick={() => refetch()}>{t('refresh')}</Button>
          <Button onClick={onClose}>{t('close')}</Button>
        </Space>
      }
    >
      <Table<AccountRow>
        rowKey="email"
        size="small"
        loading={loading}
        columns={columns}
        dataSource={rowsOnThisInbound}
        pagination={{
          current: page,
          pageSize,
          total: data?.total ?? 0,
          onChange: setPage,
          showSizeChanger: false,
        }}
      />
    </Card>
  );
}

const DEVICE_PROTOCOLS = new Set(['wg-c', 'awg', 'gre', 'ssh']);

function DeviceConfigButton({ inbound, email }: { inbound: VpnInboundRow; email: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const protocol = inbound.protocol;
  const enabled = DEVICE_PROTOCOLS.has(protocol);
  const kind = protocol as 'wg-c' | 'awg' | 'gre' | 'ssh';
  const { data, isFetching } = useVpnDeviceConfigs(
    enabled && open ? inbound.id : null,
    enabled && open ? kind : null,
    email,
  );

  const entries: DeviceConfigEntry[] = data ?? [];

  const onSaveAll = useCallback(() => {
    (data ?? []).forEach((entry, index) => {
      const text = deviceConfigText(entry);
      if (text) downloadText(`${email}-${index}.conf`, text);
    });
  }, [data, email]);

  if (!enabled) {
    return (
      <Button type="link" size="small" disabled>
        {t('pages.vpnProtocols.noConfigView')}
      </Button>
    );
  }

  return (
    <>
      <Button type="link" size="small" onClick={() => setOpen(true)}>
        {t('pages.vpnProtocols.devices')}
      </Button>
      <Modal
        open={open}
        onCancel={() => setOpen(false)}
        footer={[
          <Button key="save" type="primary" onClick={onSaveAll} disabled={!data?.length}>
            {t('download')}
          </Button>,
          <Button key="close" onClick={() => setOpen(false)}>
            {t('close')}
          </Button>,
        ]}
        title={t('pages.vpnProtocols.devicesTitle', { email })}
        width={720}
      >
        {isFetching && <Alert type="info" message={t('loading')} />}
        {!isFetching && !data?.length && <Alert type="warning" message={t('noData')} />}
        {entries.map((entry, index) => {
          const text = deviceConfigText(entry);
          return (
            <Card
              key={index}
              size="small"
              title={entry.remark || `#${index}`}
              style={{ marginBottom: 8 }}
            >
              <pre style={{ maxHeight: 180, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                {text || t('pages.vpnProtocols.configEmpty')}
              </pre>
            </Card>
          );
        })}
      </Modal>
    </>
  );
}
