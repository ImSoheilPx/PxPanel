import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  ConfigProvider,
  Descriptions,
  Layout,
  Modal,
  Result,
  Row,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useTheme } from '@/hooks/useTheme';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import AppSidebar from '@/layouts/AppSidebar';
import { setMessageInstance } from '@/utils/messageBus';
import type { CoreStatus } from '@/schemas/api/vpn';
import {
  useVpnCoreCatalog,
  useVpnCoreLogs,
  useVpnCoreMutations,
  useVpnCoreStatus,
  useVpnProvisionStatus,
  useVpnUninstallStatus,
} from '@/api/queries/useVpnCore';
import CoreConfigModal from './CoreConfigModal';

export default function CoreSettingsPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const [consoleOpen, setConsoleOpen] = useState(false);
  const [consoleMode, setConsoleMode] = useState<'provision' | 'uninstall'>('provision');
  const [logsFor, setLogsFor] = useState<string | null>(null);
  const [configFor, setConfigFor] = useState<string | null>(null);

  const { status, loading, refetch } = useVpnCoreStatus(consoleOpen ? 5000 : 20000);
  const catalog = useVpnCoreCatalog();
  const provisionRunning = useVpnProvisionStatus(consoleOpen && consoleMode === 'provision');
  const uninstallRunning = useVpnUninstallStatus(consoleOpen && consoleMode === 'uninstall');
  const {
    restart,
    restartAll,
    stop,
    reboot,
    startProvision,
    startUninstall,
  } = useVpnCoreMutations();

  const onRestart = useCallback(
    async (core: string) => {
      const msg = await restart(core);
      if (msg?.success) messageApi.success(t('pages.core.toasts.restarted'));
      else messageApi.error(msg?.msg || t('somethingWentWrong'));
    },
    [restart, messageApi, t],
  );

  const onStop = useCallback(
    (core: string) => {
      modal.confirm({
        title: t('pages.core.stopConfirm', { name: core }),
        okText: t('pages.core.stop'),
        okType: 'danger',
        cancelText: t('cancel'),
        onOk: async () => {
          const msg = await stop(core);
          if (msg?.success) messageApi.success(t('pages.core.toasts.stopped'));
          else messageApi.error(msg?.msg || t('somethingWentWrong'));
        },
      });
    },
    [modal, stop, messageApi, t],
  );

  const onRestartAll = useCallback(
    async () => {
      const msg = await restartAll();
      if (msg?.success) messageApi.success(t('pages.core.toasts.restarted'));
      else messageApi.error(msg?.msg || t('somethingWentWrong'));
    },
    [restartAll, messageApi, t],
  );

  const onReboot = useCallback(() => {
    modal.confirm({
      title: t('pages.core.rebootConfirm'),
      content: t('pages.core.rebootHint'),
      okText: t('pages.core.reboot'),
      okType: 'danger',
      cancelText: t('cancel'),
      onOk: async () => {
        const msg = await reboot();
        if (msg?.success) messageApi.success(t('pages.core.toasts.rebooting'));
        else messageApi.error(msg?.msg || t('somethingWentWrong'));
      },
    });
  }, [modal, reboot, messageApi, t]);

  const onProvision = useCallback(() => {
    const installed = new Set((status?.cores ?? []).map((core) => core.name));
    const installable = (catalog?.cores ?? []).filter(
      (entry) => !entry.builtin && !installed.has(entry.name),
    );
    if (installable.length === 0) {
      messageApi.info(t('pages.core.everythingInstalled'));
      return;
    }
    let selected = installable.map((entry) => entry.name);
    modal.confirm({
      title: t('pages.core.provisionTitle'),
      content: (
        <div>
          <p>{t('pages.core.provisionDesc')}</p>
          <Checkbox.Group
            defaultValue={selected}
            options={installable.map((entry) => ({
              label: t(`pages.core.coreNames.${entry.name}`),
              value: entry.name,
            }))}
            onChange={(checked) => {
              selected = checked as string[];
            }}
          />
        </div>
      ),
      width: 520,
      okText: t('pages.core.provision'),
      cancelText: t('cancel'),
      onOk: async () => {
        const state = await startProvision(selected);
        if (state) {
          setConsoleMode('provision');
          setConsoleOpen(true);
          void refetch();
        } else {
          messageApi.error(t('somethingWentWrong'));
        }
      },
    });
  }, [modal, catalog, status, startProvision, refetch, messageApi, t]);

  const onUninstall = useCallback(() => {
    const uninstallable = (catalog?.cores ?? []).filter(
      (entry) => entry.installed && !entry.builtin,
    );
    let selected: string[] = uninstallable.map((entry) => entry.name);
    let inboundsMode: 'delete' | 'keep' = 'delete';
    modal.confirm({
      title: t('pages.core.uninstallTitle'),
      content: (
        <div>
          <p>{t('pages.core.uninstallDesc')}</p>
          <Checkbox.Group
            defaultValue={selected}
            options={uninstallable.map((entry) => ({
              label: `${t(`pages.core.coreNames.${entry.name}`)} (${entry.inbounds})`,
              value: entry.name,
            }))}
            onChange={(checked) => {
              selected = checked as string[];
            }}
          />
          <p style={{ marginTop: 12 }}>{t('pages.core.uninstallInboundsQuestion')}</p>
          <Select
            defaultValue="delete"
            style={{ width: 240 }}
            options={[
              { value: 'delete', label: t('pages.core.uninstallDeleteInbounds') },
              { value: 'keep', label: t('pages.core.uninstallKeepInbounds') },
            ]}
            onChange={(value) => {
              inboundsMode = value as 'delete' | 'keep';
            }}
          />
        </div>
      ),
      width: 560,
      okText: t('pages.core.uninstall'),
      okType: 'danger',
      cancelText: t('cancel'),
      onOk: async () => {
        if (selected.length === 0) return;
        const state = await startUninstall(selected, inboundsMode);
        if (state) {
          setConsoleMode('uninstall');
          setConsoleOpen(true);
          void refetch();
        } else {
          messageApi.error(t('somethingWentWrong'));
        }
      },
    });
  }, [modal, catalog, startUninstall, refetch, messageApi, t]);

  const system = status?.system;
  const steps =
    consoleMode === 'provision'
      ? provisionRunning.data?.steps ?? []
      : uninstallRunning.data?.steps ?? [];
  const consoleRunning =
    consoleMode === 'provision'
      ? provisionRunning.data?.running ?? false
      : uninstallRunning.data?.running ?? false;
  const kept = uninstallRunning.data?.kept ?? [];

  const statusColumns: ColumnsType<CoreStatus> = useMemo(
    () => [
      {
        title: t('pages.core.core'),
        dataIndex: 'name',
        render: (_, row) => (
          <Space>
            <span>{t(`pages.core.coreNames.${row.name}`)}</span>
            {row.version && <Tag>{row.version}</Tag>}
          </Space>
        ),
      },
      {
        title: t('status'),
        dataIndex: 'state',
        render: (state: string) => {
          const color =
            state === 'running'
              ? 'green'
              : state === 'stopped' || state === 'uninstalled'
                ? 'red'
                : 'default';
          return <Tag color={color}>{state || '—'}</Tag>;
        },
      },
      { title: t('pages.core.detail'), dataIndex: 'detail', ellipsis: true },
      {
        title: t('pages.admins.inboundCount'),
        dataIndex: 'inbounds',
        render: (count) => count ?? 0,
      },
      {
        title: '',
        render: (_, row) => (
          <Space>
            <Button size="small" type="link" onClick={() => onRestart(row.name)}>
              {t('pages.core.restart')}
            </Button>
            <Button size="small" type="link" onClick={() => setLogsFor(row.name)}>
              {t('pages.core.logs')}
            </Button>
            <Button size="small" type="link" onClick={() => setConfigFor(row.name)}>
              {t('pages.core.config')}
            </Button>
            <Button size="small" type="link" danger onClick={() => onStop(row.name)}>
              {t('pages.core.stop')}
            </Button>
          </Space>
        ),
      },
    ],
    [t, onRestart, onStop],
  );

  const pageClass = useMemo(() => {
    const classes = ['core-settings-page'];
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
            <Spin aria-live="off" spinning={status === null && !loading} delay={200} size="large">
              <Row gutter={[isMobile ? 8 : 16, isMobile ? 8 : 12]}>
                {status?.rebootRequired && (
                  <Col span={24}>
                    <Alert
                      type="warning"
                      showIcon
                      message={t('pages.core.rebootRequired')}
                      description={
                        `${t('pages.core.rebootModules')}: ` +
                        ((status.rebootModules ?? []).join(', ') || '—') +
                        (status.rebootPkg ? ` · ${status.rebootPkg}` : '')
                      }
                      action={
                        <Button size="small" danger onClick={onReboot}>
                          {t('pages.core.reboot')}
                        </Button>
                      }
                    />
                  </Col>
                )}
                {!status?.provisioned && (
                  <Col span={24}>
                    <Alert
                      type="info"
                      showIcon
                      message={t('pages.core.notProvisioned')}
                      description={t('pages.core.notProvisionedHint')}
                      action={
                        <Button size="small" type="primary" onClick={onProvision}>
                          {t('pages.core.provision')}
                        </Button>
                      }
                    />
                  </Col>
                )}
                <Col span={24}>
                  <Card
                    size="small"
                    title={t('pages.core.title')}
                    extra={
                      <Space>
                        <Button onClick={() => refetch()}>{t('refresh')}</Button>
                        <Button onClick={onProvision}>{t('pages.core.provision')}</Button>
                        <Button danger onClick={onUninstall}>
                          {t('pages.core.uninstall')}
                        </Button>
                        <Button type="primary" onClick={onRestartAll}>
                          {t('pages.core.restartAll')}
                        </Button>
                      </Space>
                    }
                  >
                    <Table<CoreStatus>
                      rowKey="name"
                      size="small"
                      loading={loading}
                      columns={statusColumns}
                      dataSource={status?.cores ?? []}
                      pagination={false}
                      locale={{ emptyText: t('noData') }}
                    />
                  </Card>
                </Col>
                {system && (
                  <Col span={24}>
                    <Card size="small" title={t('pages.core.system')}>
                      <Descriptions size="small" column={2}>
                        <Descriptions.Item label={t('pages.core.ipForward')}>
                          <Tag color={system.ipForward ? 'green' : 'red'}>
                            {system.ipForward ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item label={t('pages.core.nftables')}>
                          <Tag color={system.nftables ? 'green' : 'red'}>
                            {system.nftables ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item label={t('pages.core.iproute')}>
                          <Tag color={system.iproute ? 'green' : 'red'}>
                            {system.iproute ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item label={t('pages.core.modules')}>
                          <Space wrap size={4}>
                            {system.modules.map((module) => (
                              <Tag
                                key={module.name}
                                color={
                                  module.loaded ? 'green' : module.optional ? 'default' : 'red'
                                }
                              >
                                {module.name}
                              </Tag>
                            ))}
                            {system.modules.length === 0 && '—'}
                          </Space>
                        </Descriptions.Item>
                      </Descriptions>
                    </Card>
                  </Col>
                )}
              </Row>
            </Spin>
          </Layout.Content>
        </Layout>

        <Modal
          open={consoleOpen}
          onCancel={() => setConsoleOpen(false)}
          footer={[
            <Button key="close" type="primary" onClick={() => setConsoleOpen(false)}>
              {t('close')}
            </Button>,
          ]}
          title={
            consoleMode === 'provision'
              ? t('pages.core.provisionConsole')
              : t('pages.core.uninstallConsole')
          }
          width={720}
        >
          <Spin spinning={consoleRunning}>
            {steps.length === 0 ? (
              <Result status="info" title={t('pages.core.consoleIdle')} />
            ) : (
              <Space direction="vertical" style={{ width: '100%' }} size={4}>
                {steps.map((step, index) => (
                  <Alert
                    key={index}
                    type={step.ok ? 'success' : 'error'}
                    showIcon
                    message={step.what}
                    description={step.detail || undefined}
                  />
                ))}
                {kept.length > 0 && (
                  <Alert
                    type="warning"
                    showIcon
                    message={t('pages.core.keptInbounds')}
                    description={kept.join(', ')}
                  />
                )}
              </Space>
            )}
          </Spin>
        </Modal>

        <LogsModal core={logsFor} onClose={() => setLogsFor(null)} />
        <CoreConfigModal core={configFor} onClose={() => setConfigFor(null)} />
      </Layout>
    </ConfigProvider>
  );
}

function LogsModal({ core, onClose }: { core: string | null; onClose: () => void }) {
  const { t } = useTranslation();
  const logs = useVpnCoreLogs(core);
  return (
    <Modal
      open={core !== null}
      onCancel={onClose}
      footer={[
        <Button key="refresh" onClick={() => void logs.refetch()}>
          {t('refresh')}
        </Button>,
        <Button key="close" type="primary" onClick={onClose}>
          {t('close')}
        </Button>,
      ]}
      title={t('pages.core.logsTitle', { core: core || '' })}
      width={860}
    >
      <pre style={{ maxHeight: 420, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
        {logs.data || t('noData')}
      </pre>
    </Modal>
  );
}
