import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Input,
  Row,
  Space,
  Spin,
  Table,
  Tag,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import type { AddressingReport, DeviceConfig, PoolBlock, SshClientConfig } from '@/schemas/api/vpn';
import { useVpnAddressing, useVpnDeviceConfigs, useVpnPools } from '@/api/queries/useVpnProtocols';
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
}

const OVPN_PROTOCOLS = new Set(['openvpn']);
const DEVICE_PROTOCOLS = new Set(['wg-c', 'awg', 'gre', 'ssh']);

/*
 * The per-inbound vpn toolbox: address-plane report, the .ovpn profile
 * downloads and the panel-wide pool map. Rendered inside the Inbound
 * Information modal's Tools tab for vpn-protocol rows (the native analog of
 * the config downloads the client panel exposes for xray inbounds).
 */
export default function ProtocolToolboxContent({ inbound }: Props) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const [poolsOpen, setPoolsOpen] = useState(false);

  const addressingQuery = useVpnAddressing(inbound.id);
  const report = addressingQuery.data;
  const addressingUnavailable = addressingQuery.data === null && !addressingQuery.isFetching;

  const [configEmail, setConfigEmail] = useState('');
  const deviceProtocol = DEVICE_PROTOCOLS.has(inbound.protocol)
    ? (inbound.protocol as 'wg-c' | 'awg' | 'gre' | 'ssh')
    : null;

  const poolsQuery = useVpnPools(poolsOpen);

  const onDownloadOvpn = useCallback(
    async (proto: 'udp' | 'tcp') => {
      try {
        const resp = await fetch(
          `${window.PXPANEL_BASE_PATH || ''}/panel/api/inbounds/${inbound.id}/ovpn/${proto}`,
          { credentials: 'same-origin' },
        );
        if (!resp.ok) throw new Error(String(resp.status));
        const text = await resp.text();
        downloadText(`client-${proto}.ovpn`, text, 'application/x-openvpn-profile');
      } catch {
        messageApi.error(t('somethingWentWrong'));
      }
    },
    [inbound, messageApi, t],
  );

  const poolColumns: ColumnsType<PoolBlock> = [
    { title: t('pages.vpnProtocols.subnet'), dataIndex: 'subnet' },
    { title: t('protocol'), dataIndex: 'protocol' },
    { title: 'ID', dataIndex: 'inboundId' },
    { title: t('remark'), dataIndex: 'remark' },
  ];

  if (poolsOpen) {
    return (
      <>
        <Space style={{ marginBottom: 8 }}>
          <Button onClick={() => setPoolsOpen(false)}>{t('close')}</Button>
        </Space>
        <Table<PoolBlock>
          rowKey={(block) => `${block.subnet}-${block.inboundId}`}
          size="small"
          loading={poolsQuery.isFetching}
          columns={poolColumns}
          dataSource={poolsQuery.data ?? []}
          pagination={false}
        />
      </>
    );
  }

  return (
    <Spin spinning={addressingQuery.isFetching} aria-live="off">
      {OVPN_PROTOCOLS.has(inbound.protocol) && (
        <Card
          size="small"
          title={t('pages.vpnProtocols.ovpnDownload')}
          style={{ marginBottom: 12 }}
        >
          <Space>
            <Button type="primary" onClick={() => onDownloadOvpn('udp')}>
              UDP
            </Button>
            <Button type="primary" onClick={() => onDownloadOvpn('tcp')}>
              TCP
            </Button>
          </Space>
        </Card>
      )}
      {deviceProtocol && (
        <Card
          size="small"
          title={t('pages.vpnProtocols.clientConfigFetch')}
          style={{ marginBottom: 12 }}
        >
          <Space wrap>
            <Input
              aria-label={t('pages.vpnProtocols.email')}
              placeholder={t('pages.vpnProtocols.email')}
              value={configEmail}
              onChange={(e) => setConfigEmail(e.target.value)}
              style={{ width: 240 }}
            />
            <ClientConfigFetchButton
              inbound={inbound}
              protocol={deviceProtocol}
              email={configEmail.trim()}
            />
          </Space>
        </Card>
      )}
      {addressingUnavailable ? (
        <Alert
          type="info"
          showIcon
          message={t('pages.vpnProtocols.noAddressPool')}
          description={t('pages.vpnProtocols.noAddressPoolHint')}
        />
      ) : report ? (
        <>
          <Card
            size="small"
            title={t('pages.vpnProtocols.addressing')}
            style={{ marginBottom: 12 }}
          >
            <Descriptions size="small" column={3}>
              <Descriptions.Item label={t('pages.vpnProtocols.ranges')}>
                {report.ranges.join(', ') || '—'}
              </Descriptions.Item>
              <Descriptions.Item label={t('pages.vpnProtocols.capacity')}>
                {report.capacity}
              </Descriptions.Item>
              <Descriptions.Item label={t('pages.vpnProtocols.used')}>
                {report.used}
              </Descriptions.Item>
              <Descriptions.Item label={t('pages.vpnProtocols.userLimit')}>
                <UserLimitText report={report} />
              </Descriptions.Item>
              <Descriptions.Item label={t('pages.vpnProtocols.maxAccounts')}>
                {report.maxAccounts || '—'}
              </Descriptions.Item>
              <Descriptions.Item label={t('pages.vpnProtocols.subnets')}>
                {report.subnets.join(', ') || '—'}
              </Descriptions.Item>
            </Descriptions>
          </Card>
          <Card size="small" title={t('pages.vpnProtocols.accountAddresses')}>
            <Row gutter={[8, 4]}>
              {report.accounts.length === 0 && <Col span={24}>{t('noData')}</Col>}
              {report.accounts.map((account) => (
                <Col xs={24} md={12} key={account.email}>
                  <Space wrap size={4}>
                    <span>{account.email}</span>
                    <Tag>#{account.slot}</Tag>
                    {account.addresses.map((address) => (
                      <Tag key={address}>{address}</Tag>
                    ))}
                  </Space>
                </Col>
              ))}
            </Row>
          </Card>
        </>
      ) : null}
      <Space style={{ marginTop: 12 }}>
        <Button onClick={() => setPoolsOpen(true)}>{t('pages.vpnProtocols.pools')}</Button>
      </Space>
    </Spin>
  );
}

function ClientConfigFetchButton({
  inbound,
  protocol,
  email,
}: {
  inbound: VpnInboundRow;
  protocol: 'wg-c' | 'awg' | 'gre' | 'ssh';
  email: string;
}) {
  const { t } = useTranslation();
  const enabled = email !== '';
  const { data, isFetching } = useVpnDeviceConfigs(
    enabled ? inbound.id : null,
    enabled ? protocol : null,
    email,
  );

  const onSave = useCallback(() => {
    (data ?? []).forEach((entry, index) => {
      const text = deviceConfigText(entry);
      if (text) downloadText(`${email}-${index}.conf`, text);
    });
  }, [data, email]);

  return (
    <Button loading={isFetching} disabled={!enabled || !data} onClick={onSave}>
      {t('download')}
    </Button>
  );
}

function UserLimitText({ report }: { report: AddressingReport }) {
  const posted = report.userLimit.posted;
  const rule = report.userLimit.rule;
  if (posted === null || posted === undefined) {
    return <span>{`${report.userLimit.effective} (${rule})`}</span>;
  }
  return <span>{`${posted} → ${report.userLimit.effective} (${rule})`}</span>;
}
