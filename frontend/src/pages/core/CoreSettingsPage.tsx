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
  Form,
  Layout,
  Modal,
  Result,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tag,
  Tooltip,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  ApartmentOutlined,
  CheckCircleOutlined,
  ClusterOutlined,
  DownloadOutlined,
  FileTextOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SettingOutlined,
  SyncOutlined,
} from '@ant-design/icons';

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
import { FileManager } from '@/utils';
import { activateOnKey } from '@/utils/a11y';
import { LEVELS, parseLogLine } from '../index/logParse';
import '../index/LogModal.css';
import CoreConfigModal from './CoreConfigModal';
import './CoreSettingsPage.css';

// Localized tag colors per backend CoreState (internal/vpn/coresettings/status.go):
// running is healthy, stopped/error are faults, idle and not_installed are
// expected states a core rests in until the operator acts on it.
const STATE_TAG_COLORS: Record<string, string> = {
  running: 'green',
  stopped: 'red',
  error: 'volcano',
  idle: 'default',
  not_installed: 'default',
};

function CoreStateTag({ state }: { state: string }) {
  const { t } = useTranslation();
  const key = state || 'unknown';
  return (
    <Tag color={STATE_TAG_COLORS[key] ?? 'default'}>
      {t(`pages.core.states.${key}`, { defaultValue: state || '—' })}
    </Tag>
  );
}

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
  const { restart, restartAll, stop, reboot, startProvision, startUninstall } =
    useVpnCoreMutations();

  // Cores the catalog offers as real install targets (non-builtin). A row gets
  // its Install button only when BOTH the status says not_installed AND the
  // catalog lists the core here: ipsec and radius are derived rows with no
  // install step of their own, and posting them to the provision endpoint
  // would be filtered out server-side and fall through to an all-cores run.
  const installableNames = useMemo(() => {
    const names = new Set<string>();
    for (const entry of catalog?.cores ?? []) {
      if (!entry.builtin) names.add(entry.name);
    }
    return names;
  }, [catalog]);

  const stats = useMemo(() => {
    let running = 0;
    let notInstalled = 0;
    let inbounds = 0;
    for (const core of status?.cores ?? []) {
      if (core.state === 'running') running += 1;
      if (core.state === 'not_installed') notInstalled += 1;
      inbounds += core.inbounds ?? 0;
    }
    return { total: status?.cores.length ?? 0, running, notInstalled, inbounds };
  }, [status]);

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

  const onRestartAll = useCallback(async () => {
    const msg = await restartAll();
    if (msg?.success) messageApi.success(t('pages.core.toasts.restarted'));
    else messageApi.error(msg?.msg || t('somethingWentWrong'));
  }, [restartAll, messageApi, t]);

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

  // Per-core install: the same background provisioning the all-cores setup
  // runs, scoped to one core via the `cores` form field (POST
  // /panel/api/core/provision). The shared console shows the live per-step
  // progress; the backend brings the core's daemons up when it finishes.
  const onInstall = useCallback(
    (core: string) => {
      modal.confirm({
        title: t('pages.core.installConfirm', { name: t(`pages.core.coreNames.${core}`) }),
        content: t('pages.core.installDesc'),
        okText: t('pages.core.install'),
        cancelText: t('cancel'),
        onOk: async () => {
          const state = await startProvision([core]);
          if (state) {
            setConsoleMode('provision');
            setConsoleOpen(true);
            void refetch();
          } else {
            messageApi.error(t('somethingWentWrong'));
          }
        },
      });
    },
    [modal, startProvision, refetch, messageApi, t],
  );

  const onProvision = useCallback(() => {
    // The catalog's own installed flag is the authoritative install state; the
    // status rows name every core whether installed or not, so they cannot
    // drive this picker.
    const installable = (catalog?.cores ?? []).filter(
      (entry) => !entry.builtin && !entry.installed,
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
  }, [modal, catalog, startProvision, refetch, messageApi, t]);

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
          <Tooltip title={t('pages.core.uninstallInboundsModeHint')}>
            <Select
              defaultValue="delete"
              style={{ width: 240 }}
              aria-label={t('pages.core.uninstallInboundsQuestion')}
              options={[
                { value: 'delete', label: t('pages.core.uninstallDeleteInbounds') },
                { value: 'keep', label: t('pages.core.uninstallKeepInbounds') },
              ]}
              onChange={(value) => {
                inboundsMode = value as 'delete' | 'keep';
              }}
            />
          </Tooltip>
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
      ? (provisionRunning.data?.steps ?? [])
      : (uninstallRunning.data?.steps ?? []);
  const consoleRunning =
    consoleMode === 'provision'
      ? (provisionRunning.data?.running ?? false)
      : (uninstallRunning.data?.running ?? false);
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
        render: (state: string) => <CoreStateTag state={state} />,
      },
      { title: t('pages.core.detail'), dataIndex: 'detail', ellipsis: true },
      {
        title: t('pages.core.inbounds'),
        dataIndex: 'inbounds',
        align: 'center',
        render: (count) => count ?? 0,
      },
      {
        title: t('pages.core.actions'),
        key: 'actions',
        width: 200,
        render: (_, row) => {
          if (row.state === 'not_installed') {
            // Only catalog install targets get the button; derived rows
            // (ipsec, radius) have nothing of their own to install.
            return installableNames.has(row.name) ? (
              <Tooltip title={t('pages.core.installHint')}>
                <Button
                  size="small"
                  type="primary"
                  icon={<DownloadOutlined aria-hidden />}
                  onClick={() => onInstall(row.name)}
                >
                  {t('pages.core.install')}
                </Button>
              </Tooltip>
            ) : (
              <span style={{ opacity: 0.4 }}>—</span>
            );
          }
          return (
            <Space size={0}>
              {(row.state === 'stopped' || row.state === 'error') && (
                <Tooltip title={t('pages.core.startHint')}>
                  <Button
                    type="text"
                    size="small"
                    style={{ fontSize: 16 }}
                    icon={<PlayCircleOutlined aria-hidden />}
                    aria-label={t('pages.core.start')}
                    onClick={() => onRestart(row.name)}
                  />
                </Tooltip>
              )}
              <Tooltip title={t('pages.core.restartHint')}>
                <Button
                  type="text"
                  size="small"
                  style={{ fontSize: 16 }}
                  icon={<ReloadOutlined aria-hidden />}
                  aria-label={t('pages.core.restart')}
                  onClick={() => onRestart(row.name)}
                />
              </Tooltip>
              <Tooltip title={t('pages.core.logsHint')}>
                <Button
                  type="text"
                  size="small"
                  style={{ fontSize: 16 }}
                  icon={<FileTextOutlined aria-hidden />}
                  aria-label={t('pages.core.logs')}
                  onClick={() => setLogsFor(row.name)}
                />
              </Tooltip>
              <Tooltip title={t('pages.core.configHint')}>
                <Button
                  type="text"
                  size="small"
                  style={{ fontSize: 16 }}
                  icon={<SettingOutlined aria-hidden />}
                  aria-label={t('pages.core.config')}
                  onClick={() => setConfigFor(row.name)}
                />
              </Tooltip>
              {row.state === 'running' && (
                <Tooltip title={t('pages.core.stopHint')}>
                  <Button
                    type="text"
                    size="small"
                    danger
                    style={{ fontSize: 16 }}
                    icon={<PauseCircleOutlined aria-hidden />}
                    aria-label={t('pages.core.stop')}
                    onClick={() => onStop(row.name)}
                  />
                </Tooltip>
              )}
            </Space>
          );
        },
      },
    ],
    [t, installableNames, onInstall, onRestart, onStop],
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
                        <Tooltip title={t('pages.core.rebootHint')}>
                          <Button size="small" danger onClick={onReboot}>
                            {t('pages.core.reboot')}
                          </Button>
                        </Tooltip>
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
                        <Tooltip title={t('pages.core.provisionHint')}>
                          <Button size="small" type="primary" onClick={onProvision}>
                            {t('pages.core.provision')}
                          </Button>
                        </Tooltip>
                      }
                    />
                  </Col>
                )}
                <Col span={24}>
                  <Card size="small" hoverable className="summary-card">
                    <Row gutter={[16, isMobile ? 16 : 12]}>
                      <Col xs={12} md={6}>
                        <Statistic
                          title={t('pages.core.stats.cores')}
                          value={stats.total}
                          prefix={<ClusterOutlined aria-hidden />}
                        />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic
                          title={t('pages.core.stats.running')}
                          value={stats.running}
                          prefix={
                            <CheckCircleOutlined
                              aria-hidden
                              style={{ color: 'var(--ant-color-success)' }}
                            />
                          }
                        />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic
                          title={t('pages.core.stats.notInstalled')}
                          value={stats.notInstalled}
                          prefix={
                            <DownloadOutlined
                              aria-hidden
                              style={{ color: 'var(--ant-color-warning)' }}
                            />
                          }
                        />
                      </Col>
                      <Col xs={12} md={6}>
                        <Statistic
                          title={t('pages.core.stats.inbounds')}
                          value={stats.inbounds}
                          prefix={<ApartmentOutlined aria-hidden />}
                        />
                      </Col>
                    </Row>
                  </Card>
                </Col>
                <Col span={24}>
                  <Card size="small" hoverable title={t('pages.core.coresCard')}>
                    <div className="toolbar">
                      <Tooltip title={t('pages.core.refreshHint')}>
                        <Button icon={<ReloadOutlined aria-hidden />} onClick={() => refetch()}>
                          {t('refresh')}
                        </Button>
                      </Tooltip>
                      <Space wrap>
                        <Tooltip title={t('pages.core.provisionHint')}>
                          <Button onClick={onProvision}>{t('pages.core.provision')}</Button>
                        </Tooltip>
                        <Tooltip title={t('pages.core.uninstallHint')}>
                          <Button danger onClick={onUninstall}>
                            {t('pages.core.uninstall')}
                          </Button>
                        </Tooltip>
                        <Tooltip title={t('pages.core.restartAllHint')}>
                          <Button type="primary" onClick={onRestartAll}>
                            {t('pages.core.restartAll')}
                          </Button>
                        </Tooltip>
                      </Space>
                    </div>
                    <Table<CoreStatus>
                      rowKey="name"
                      size="small"
                      loading={loading}
                      columns={statusColumns}
                      dataSource={status?.cores ?? []}
                      pagination={false}
                      scroll={{ x: 'max-content' }}
                      locale={{ emptyText: t('noData') }}
                    />
                  </Card>
                </Col>
                {system && (
                  <Col span={24}>
                    <Card size="small" hoverable title={t('pages.core.system')}>
                      <Descriptions size="small" column={2}>
                        <Descriptions.Item
                          label={
                            <Tooltip title={t('pages.core.ipForwardHint')}>
                              <span>{t('pages.core.ipForward')}</span>
                            </Tooltip>
                          }
                        >
                          <Tag color={system.ipForward ? 'green' : 'red'}>
                            {system.ipForward ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item
                          label={
                            <Tooltip title={t('pages.core.nftablesHint')}>
                              <span>{t('pages.core.nftables')}</span>
                            </Tooltip>
                          }
                        >
                          <Tag color={system.nftables ? 'green' : 'red'}>
                            {system.nftables ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item
                          label={
                            <Tooltip title={t('pages.core.iprouteHint')}>
                              <span>{t('pages.core.iproute')}</span>
                            </Tooltip>
                          }
                        >
                          <Tag color={system.iproute ? 'green' : 'red'}>
                            {system.iproute ? t('enabled') : t('disabled')}
                          </Tag>
                        </Descriptions.Item>
                        <Descriptions.Item
                          label={
                            <Tooltip title={t('pages.core.modulesHint')}>
                              <span>{t('pages.core.modules')}</span>
                            </Tooltip>
                          }
                        >
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
          <Spin spinning={consoleRunning} aria-live="off">
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
  const { isMobile } = useMediaQuery();
  const [rows, setRows] = useState('20');
  const [level, setLevel] = useState('debug');
  const [autoUpdate, setAutoUpdate] = useState(false);
  const logs = useVpnCoreLogs(core, autoUpdate ? 5000 : 0);

  const allLines = useMemo(() => (logs.data ? logs.data.split('\n') : []), [logs.data]);
  // Trim to the last N lines, then parse with the same renderer the panel log
  // viewer uses, so a core's log looks exactly like the panel's own log page.
  const parsedLogs = useMemo(() => {
    const trimmed = allLines.slice(-parseInt(rows, 10));
    return trimmed.map(parseLogLine);
  }, [allLines, rows]);

  // Client-side level filter, mirroring the panel log endpoint's semantics:
  // show the selected level and everything above it; entries without a
  // recognizable level (raw daemon output) always stay visible.
  const selectedLevelIdx =
    level === 'err' ? LEVELS.indexOf('ERROR') : LEVELS.indexOf(level.toUpperCase());
  const visibleLogs = useMemo(
    () =>
      parsedLogs.filter((log) => {
        if (selectedLevelIdx < 0) return true;
        if (!log.levelText) return true;
        const lineIdx = LEVELS.indexOf(log.levelText.toUpperCase());
        return lineIdx < 0 || lineIdx >= selectedLevelIdx;
      }),
    [parsedLogs, selectedLevelIdx],
  );

  function download() {
    FileManager.downloadTextFile((logs.data || '').replace(/\n+$/, ''), 'pxpanel.log');
  }

  const refresh = useCallback(() => void logs.refetch(), [logs]);
  const titleNode = (
    <>
      {t('pages.core.logsTitle', { core: core || '' })}
      <SyncOutlined
        spin={logs.isFetching}
        className="reload-icon"
        role="button"
        tabIndex={0}
        aria-label={t('refresh')}
        onClick={refresh}
        onKeyDown={activateOnKey(refresh)}
      />
    </>
  );

  return (
    <Modal
      open={core !== null}
      onCancel={onClose}
      footer={null}
      width={isMobile ? '100vw' : 860}
      style={isMobile ? { top: 0, paddingBottom: 0, maxWidth: '100vw' } : undefined}
      className={isMobile ? 'logmodal-mobile' : undefined}
      title={titleNode}
    >
      <Form layout="inline" className="log-toolbar">
        <Form.Item>
          <Space.Compact>
            <Select
              aria-label={t('pages.index.logLines')}
              value={rows}
              size="small"
              style={{ width: 100 }}
              onChange={setRows}
              options={[
                { value: '20', label: '20' },
                { value: '50', label: '50' },
                { value: '100', label: '100' },
                { value: '500', label: '500' },
                { value: '1000', label: '1000' },
              ]}
            />
            <Select
              aria-label={t('pages.xray.logLevel')}
              value={level}
              size="small"
              style={{ minWidth: 95 }}
              onChange={setLevel}
              options={[
                { value: 'debug', label: t('pages.index.logLevelDebug') },
                { value: 'info', label: t('pages.index.logLevelInfo') },
                { value: 'notice', label: t('pages.index.logLevelNotice') },
                { value: 'warning', label: t('pages.index.logLevelWarning') },
                { value: 'err', label: t('pages.index.logLevelError') },
              ]}
            />
          </Space.Compact>
        </Form.Item>
        <Form.Item>
          <Checkbox checked={autoUpdate} onChange={(e) => setAutoUpdate(e.target.checked)}>
            {t('pages.index.autoUpdate')}
          </Checkbox>
        </Form.Item>
        <Form.Item className="download-item">
          <Button
            type="primary"
            onClick={download}
            icon={<DownloadOutlined aria-hidden />}
            aria-label={t('download')}
          />
        </Form.Item>
      </Form>

      <div className={`log-container ${isMobile ? 'log-container-mobile' : ''}`}>
        {visibleLogs.length === 0 ? (
          <div className="log-empty">{t('noData')}</div>
        ) : isMobile ? (
          visibleLogs.map((log, idx) => (
            <div key={idx} className="log-card">
              <div className="log-card-head">
                {log.stamp && (
                  <span className="log-time">
                    {log.time && <span>{log.time}</span>}
                    {log.time && log.date ? ' ' : ''}
                    {log.date && <span className="log-date">{log.date}</span>}
                  </span>
                )}
                {log.levelText && (
                  <span className={`log-level-badge ${log.levelClass}`}>{log.levelText}</span>
                )}
              </div>
              {(log.body || log.service) && (
                <div className="log-body">
                  {log.service && <b>{log.service}</b>}
                  {log.service && log.body ? ' ' : ''}
                  {log.body && <span className="log-body-text">{log.body}</span>}
                </div>
              )}
            </div>
          ))
        ) : (
          visibleLogs.map((log, idx) => (
            <div key={idx} className="log-line">
              {log.stamp && <span className="log-stamp">{log.stamp}</span>}
              {log.stamp && log.levelText ? ' ' : ''}
              {log.levelText && (
                <span className={`log-level ${log.levelClass}`}>{log.levelText}</span>
              )}
              {(log.body || log.service) && (
                <>
                  {(log.stamp || log.levelText) && <span> - </span>}
                  {log.service && <b>{log.service}</b>}
                  {log.service && log.body ? ' ' : ''}
                  <span>{log.body}</span>
                </>
              )}
            </div>
          ))
        )}
      </div>
    </Modal>
  );
}
