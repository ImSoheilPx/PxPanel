import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  Col,
  ConfigProvider,
  Layout,
  Modal,
  Result,
  Row,
  Space,
  Spin,
  Tabs,
  Tag,
  message,
} from 'antd';

import { useTheme } from '@/hooks/useTheme';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import AppSidebar from '@/layouts/AppSidebar';
import { setMessageInstance } from '@/utils/messageBus';
import { VPN_PROTOCOLS, type VpnProtocol } from '@/schemas/api/vpn';
import {
  useVpnInbounds,
  useVpnProtocolMutations,
  type VpnInboundRow,
} from '@/api/queries/useVpnProtocols';
import ProtocolInboundModal from './ProtocolInboundModal';
import ProtocolAccountsCard from './ProtocolAccountsCard';
import ProtocolToolboxModal from './ProtocolToolboxModal';

function ipRangeCount(inbound: VpnInboundRow): number {
  const ranges = inbound.settings.ipRanges as string[] | undefined;
  return ranges?.length ?? 0;
}

export default function VpnProtocolsPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const { inbounds, loading, fetched, fetchError, refetch } = useVpnInbounds();
  const { deleteInbound, setEnable } = useVpnProtocolMutations();

  const [protocol, setProtocol] = useState<VpnProtocol>(VPN_PROTOCOLS[0]);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<VpnInboundRow | null>(null);
  const [toolboxFor, setToolboxFor] = useState<VpnInboundRow | null>(null);
  const [accountsFor, setAccountsFor] = useState<VpnInboundRow | null>(null);

  const scoped = useMemo(
    () => inbounds.filter((inbound) => inbound.protocol === protocol),
    [inbounds, protocol],
  );

  const onAdd = useCallback(() => {
    setEditing(null);
    setFormOpen(true);
  }, []);

  const onEdit = useCallback((inbound: VpnInboundRow) => {
    setEditing(inbound);
    setFormOpen(true);
  }, []);

  const onDelete = useCallback(
    (inbound: VpnInboundRow) => {
      modal.confirm({
        title: t('pages.vpnProtocols.deleteConfirm', { name: inbound.remark }),
        okText: t('delete'),
        okType: 'danger',
        cancelText: t('cancel'),
        onOk: async () => {
          const msg = await deleteInbound(inbound.id);
          if (msg?.success) messageApi.success(t('pages.vpnProtocols.toasts.deleted'));
          else messageApi.error(msg?.msg || t('somethingWentWrong'));
        },
      });
    },
    [modal, t, deleteInbound, messageApi],
  );

  const onToggle = useCallback(
    async (inbound: VpnInboundRow, enable: boolean) => {
      const msg = await setEnable(inbound.id, enable);
      if (!msg?.success) messageApi.error(msg?.msg || t('somethingWentWrong'));
    },
    [setEnable, messageApi, t],
  );

  const protocolTabs = useMemo(
    () =>
      VPN_PROTOCOLS.map((p) => ({
        key: p,
        label: (
          <span>
            {t(`pages.vpnProtocols.protocolNames.${p}`)}
            <Tag style={{ marginLeft: 8 }} color={p === protocol ? 'blue' : 'default'}>
              {inbounds.filter((inbound) => inbound.protocol === p).length}
            </Tag>
          </span>
        ),
      })),
    [inbounds, protocol, t],
  );

  const pageClass = useMemo(() => {
    const classes = ['vpn-protocols-page'];
    if (isDark) classes.push('is-dark');
    if (isUltra) classes.push('is-ultra');
    return classes.join(' ');
  }, [isDark, isUltra]);

  return (
    <ConfigProvider theme={antdThemeConfig}>
      {messageContextHolder}
      {modalContextHolder}
      <Layout className={pageClass}>
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Spin aria-live="off" spinning={!fetched} delay={200} size="large">
              {!fetched ? (
                <div className="loading-spacer" />
              ) : fetchError ? (
                <Result
                  status="error"
                  title={t('somethingWentWrong')}
                  subTitle={fetchError}
                  extra={
                    <Button type="primary" loading={loading} onClick={() => refetch()}>
                      {t('refresh')}
                    </Button>
                  }
                />
              ) : (
                <Row gutter={[isMobile ? 8 : 16, isMobile ? 8 : 12]}>
                  <Col span={24}>
                    <Tabs
                      activeKey={protocol}
                      items={protocolTabs}
                      onChange={(key) => setProtocol(key as VpnProtocol)}
                    />
                  </Col>
                  <Col span={24}>
                    <Card
                      size="small"
                      title={t('pages.vpnProtocols.inboundsTitle', {
                        protocol: t(`pages.vpnProtocols.protocolNames.${protocol}`),
                      })}
                      extra={
                        <Space>
                          <Button onClick={() => refetch()}>{t('refresh')}</Button>
                          <Button type="primary" onClick={onAdd}>
                            {t('pages.vpnProtocols.addInbound')}
                          </Button>
                        </Space>
                      }
                    >
                      {scoped.length === 0 ? (
                        <Result
                          status="info"
                          title={t('noData')}
                          subTitle={t('pages.vpnProtocols.emptyHint')}
                        />
                      ) : (
                        <Row gutter={[isMobile ? 8 : 12, isMobile ? 8 : 12]}>
                          {scoped.map((inbound) => (
                            <Col xs={24} lg={12} key={inbound.id}>
                              <Card
                                size="small"
                                hoverable
                                title={
                                  <Space wrap>
                                    <Tag
                                      color={inbound.enable ? 'success' : 'default'}
                                      onClick={() => onToggle(inbound, !inbound.enable)}
                                      style={{ cursor: 'pointer' }}
                                    >
                                      {inbound.enable ? t('enabled') : t('disabled')}
                                    </Tag>
                                    <span>{inbound.remark || `#${inbound.id}`}</span>
                                    <Tag>{inbound.port || '—'}</Tag>
                                  </Space>
                                }
                                actions={[
                                  <Button
                                    key="accounts"
                                    type="link"
                                    size="small"
                                    onClick={() => setAccountsFor(inbound)}
                                  >
                                    {t('pages.vpnProtocols.accounts')}
                                  </Button>,
                                  <Button
                                    key="toolbox"
                                    type="link"
                                    size="small"
                                    onClick={() => setToolboxFor(inbound)}
                                  >
                                    {t('pages.vpnProtocols.toolbox')}
                                  </Button>,
                                  <Button
                                    key="edit"
                                    type="link"
                                    size="small"
                                    onClick={() => onEdit(inbound)}
                                  >
                                    {t('edit')}
                                  </Button>,
                                  <Button
                                    key="delete"
                                    type="link"
                                    size="small"
                                    danger
                                    onClick={() => onDelete(inbound)}
                                  >
                                    {t('delete')}
                                  </Button>,
                                ]}
                              >
                                <Row gutter={[8, 4]}>
                                  <Col span={12}>{`#${inbound.id}`}</Col>
                                  <Col span={12}>
                                    {t('protocol')}: {inbound.protocol}
                                  </Col>
                                  <Col span={12}>
                                    {t('pages.vpnProtocols.listen')}: {inbound.listen || '—'}
                                  </Col>
                                  <Col span={12}>
                                    {t('pages.vpnProtocols.ipRanges')}:{' '}
                                    {ipRangeCount(inbound)}
                                  </Col>
                                </Row>
                              </Card>
                            </Col>
                          ))}
                        </Row>
                      )}
                    </Card>
                  </Col>
                  {accountsFor && (
                    <Col span={24}>
                      <ProtocolAccountsCard
                        inbound={accountsFor}
                        onClose={() => setAccountsFor(null)}
                      />
                    </Col>
                  )}
                </Row>
              )}
            </Spin>
          </Layout.Content>
        </Layout>

        <ProtocolInboundModal
          open={formOpen}
          protocol={protocol}
          inbound={editing}
          onClose={() => setFormOpen(false)}
        />
        <ProtocolToolboxModal
          inbound={toolboxFor}
          onClose={() => setToolboxFor(null)}
        />
      </Layout>
    </ConfigProvider>
  );
}
