import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  Col,
  ConfigProvider,
  Form,
  Input,
  InputNumber,
  Layout,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Tooltip,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useTheme } from '@/hooks/useTheme';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import AppSidebar from '@/layouts/AppSidebar';
import { setMessageInstance } from '@/utils/messageBus';
import type { SshOutboundConfig, VpnOutboundConfig } from '@/schemas/api/vpn';
import {
  useSshOutboundsQuery,
  useSshOutboundMutations,
  useVpnOutboundsQuery,
  useVpnOutboundMutations,
  type SshTunnelFormValues,
  type VpnTunnelFormValues,
} from '@/api/queries/useVpnOutbounds';

export default function VpnOutboundsPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const vpn = useVpnOutboundsQuery();
  const ssh = useSshOutboundsQuery();
  const vpnMut = useVpnOutboundMutations();
  const sshMut = useSshOutboundMutations();

  const [vpnForm, setVpnForm] = useState<VpnTunnelFormValues | null>(null);
  const [sshForm, setSshForm] = useState<SshTunnelFormValues | null>(null);

  const vpnColumns: ColumnsType<VpnOutboundConfig> = [
    { title: 'Tag', dataIndex: 'tag' },
    { title: t('pages.vpnOutbounds.kind'), dataIndex: 'kind' },
    { title: t('remark'), dataIndex: 'remark' },
    {
      title: t('pages.vpnOutbounds.via'),
      dataIndex: 'via',
      render: (via) => via || '—',
    },
    {
      title: t('pages.vpnOutbounds.iface'),
      dataIndex: 'iface',
      render: (iface) => iface || '—',
    },
    {
      title: t('enable'),
      dataIndex: 'enable',
      render: (enable) => (
        <Tag color={enable ? 'success' : 'default'}>{enable ? t('enabled') : t('disabled')}</Tag>
      ),
    },
    {
      title: t('status'),
      render: (_, row) => (
        <StatusButton
          onCheck={() => vpnMut.status(row.tag)}
          renderRunning={(running) => (
            <Tag color={running ? 'green' : 'red'}>
              {running ? t('pages.vpnOutbounds.running') : t('pages.vpnOutbounds.stopped')}
            </Tag>
          )}
        />
      ),
    },
    {
      title: '',
      render: (_, row) => (
        <Space>
          <Button
            size="small"
            type="link"
            onClick={() =>
              setVpnForm({
                tag: row.tag,
                kind: row.kind,
                remark: row.remark,
                enable: row.enable,
                via: row.via,
                settings: '',
              })
            }
          >
            {t('edit')}
          </Button>
          <Button
            size="small"
            type="link"
            danger
            onClick={() =>
              modal.confirm({
                title: t('pages.vpnOutbounds.deleteConfirm', { name: row.tag }),
                okText: t('delete'),
                okType: 'danger',
                cancelText: t('cancel'),
                onOk: async () => {
                  const msg = await vpnMut.remove(row.tag);
                  if (msg?.success) messageApi.success(t('pages.vpnOutbounds.toasts.deleted'));
                  else messageApi.error(msg?.msg || t('somethingWentWrong'));
                },
              })
            }
          >
            {t('delete')}
          </Button>
        </Space>
      ),
    },
  ];

  const sshColumns: ColumnsType<SshOutboundConfig> = [
    { title: 'Tag', dataIndex: 'tag' },
    { title: t('pages.vpnOutbounds.address'), render: (_, row) => `${row.address}:${row.port}` },
    { title: t('pages.vpnOutbounds.username'), dataIndex: 'username' },
    { title: t('pages.vpnOutbounds.authType'), dataIndex: 'authType' },
    {
      title: t('pages.vpnOutbounds.socksPort'),
      dataIndex: 'socksPort',
      render: (port) => port || '—',
    },
    {
      title: t('status'),
      render: (_, row) => (
        <StatusButton
          onCheck={() => sshMut.status(row.tag)}
          renderRunning={(running) => (
            <Tag color={running ? 'green' : 'red'}>
              {running ? t('pages.vpnOutbounds.running') : t('pages.vpnOutbounds.stopped')}
            </Tag>
          )}
        />
      ),
    },
    {
      title: '',
      render: (_, row) => (
        <Space>
          <Button
            size="small"
            type="link"
            onClick={() =>
              setSshForm({
                tag: row.tag,
                remark: row.remark,
                address: row.address,
                port: row.port || 22,
                username: row.username,
                authType: row.authType === 'privateKey' ? 'privateKey' : 'password',
                password: '',
                privateKey: '',
                passphrase: '',
                knownHost: row.knownHost,
              })
            }
          >
            {t('edit')}
          </Button>
          <Button
            size="small"
            type="link"
            danger
            onClick={() =>
              modal.confirm({
                title: t('pages.vpnOutbounds.deleteConfirm', { name: row.tag }),
                okText: t('delete'),
                okType: 'danger',
                cancelText: t('cancel'),
                onOk: async () => {
                  const msg = await sshMut.remove(row.tag);
                  if (msg?.success) messageApi.success(t('pages.vpnOutbounds.toasts.deleted'));
                  else messageApi.error(msg?.msg || t('somethingWentWrong'));
                },
              })
            }
          >
            {t('delete')}
          </Button>
        </Space>
      ),
    },
  ];

  const pageClass = useMemo(() => {
    const classes = ['vpn-outbounds-page'];
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
            <Spin aria-live="off" spinning={vpn.loading || ssh.loading} delay={200}>
              <Row gutter={[isMobile ? 8 : 16, isMobile ? 8 : 12]}>
                <Col span={24}>
                  <Card
                    size="small"
                    title={t('pages.vpnOutbounds.vpnTitle')}
                    extra={
                      <Space>
                        <Button onClick={() => vpn.refetch()}>{t('refresh')}</Button>
                        <Button
                          type="primary"
                          onClick={() =>
                            setVpnForm({
                              tag: '',
                              kind: '',
                              remark: '',
                              enable: true,
                              via: '',
                              settings: '',
                            })
                          }
                        >
                          {t('pages.vpnOutbounds.addTunnel')}
                        </Button>
                      </Space>
                    }
                  >
                    <Table<VpnOutboundConfig>
                      rowKey="tag"
                      size="small"
                      loading={vpn.loading}
                      columns={vpnColumns}
                      dataSource={vpn.tunnels}
                      pagination={false}
                      locale={{ emptyText: t('noData') }}
                    />
                  </Card>
                </Col>
                <Col span={24}>
                  <Card
                    size="small"
                    title={t('pages.vpnOutbounds.sshTitle')}
                    extra={
                      <Space>
                        <Button onClick={() => ssh.refetch()}>{t('refresh')}</Button>
                        <Button
                          type="primary"
                          onClick={() =>
                            setSshForm({
                              tag: '',
                              remark: '',
                              address: '',
                              port: 22,
                              username: 'root',
                              authType: 'password',
                              password: '',
                              privateKey: '',
                              passphrase: '',
                              knownHost: '',
                            })
                          }
                        >
                          {t('pages.vpnOutbounds.addTunnel')}
                        </Button>
                      </Space>
                    }
                  >
                    <Table<SshOutboundConfig>
                      rowKey="tag"
                      size="small"
                      loading={ssh.loading}
                      columns={sshColumns}
                      dataSource={ssh.tunnels}
                      pagination={false}
                      locale={{ emptyText: t('noData') }}
                    />
                  </Card>
                </Col>
              </Row>
            </Spin>
          </Layout.Content>
        </Layout>

        <VpnTunnelModal
          values={vpnForm}
          kinds={vpn.kinds}
          existingTags={vpn.tunnels.map((tunnel) => tunnel.tag)}
          onClose={() => setVpnForm(null)}
          onSave={async (values) => {
            const msg = await vpnMut.save(values);
            if (msg?.success) {
              messageApi.success(t('pages.vpnOutbounds.toasts.saved'));
              setVpnForm(null);
            } else {
              messageApi.error(msg?.msg || t('somethingWentWrong'));
            }
          }}
        />
        <SshTunnelModal
          values={sshForm}
          onClose={() => setSshForm(null)}
          onSave={async (values) => {
            const msg = await sshMut.save(values);
            if (msg?.success) {
              messageApi.success(t('pages.vpnOutbounds.toasts.saved'));
              setSshForm(null);
            } else {
              messageApi.error(msg?.msg || t('somethingWentWrong'));
            }
          }}
        />
      </Layout>
    </ConfigProvider>
  );
}

function StatusButton({
  onCheck,
  renderRunning,
}: {
  onCheck: () => Promise<{ running: boolean } | null>;
  renderRunning: (running: boolean) => ReactNode;
}) {
  const { t } = useTranslation();
  const [checking, setChecking] = useState(false);
  const [running, setRunning] = useState<boolean | null>(null);

  const onProbe = useCallback(async () => {
    setChecking(true);
    try {
      const state = await onCheck();
      setRunning(state ? state.running : null);
      if (!state) setChecking(false);
    } finally {
      setChecking(false);
    }
  }, [onCheck]);

  return (
    <Space>
      {running !== null && renderRunning(running)}
      <Tooltip title={t('pages.vpnOutbounds.probe')}>
        <Button size="small" loading={checking} onClick={onProbe}>
          {t('check')}
        </Button>
      </Tooltip>
    </Space>
  );
}

function VpnTunnelModal({
  values,
  kinds,
  existingTags,
  onClose,
  onSave,
}: {
  values: VpnTunnelFormValues | null;
  kinds: { kind: string; available: boolean; why: string }[];
  existingTags: string[];
  onClose: () => void;
  onSave: (values: VpnTunnelFormValues) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const [form] = Form.useForm<VpnTunnelFormValues>();
  useEffect(() => {
    if (values) form.setFieldsValue(values);
  }, [values, form]);

  const kindOptions = useMemo(
    () =>
      kinds.map((entry) => ({
        value: entry.kind,
        label: entry.available
          ? entry.kind
          : `${entry.kind} — ${entry.why || t('pages.vpnOutbounds.unavailable')}`,
        disabled: !entry.available,
      })),
    [kinds, t],
  );

  const onSubmit = useCallback(async () => {
    const parsed = await form.validateFields();
    const settingsRaw = (parsed.settings ?? '').trim();
    if (settingsRaw !== '') {
      try {
        JSON.parse(settingsRaw);
      } catch {
        messageApi.error(t('pages.vpnOutbounds.toasts.badSettingsJson'));
        return;
      }
    }
    await onSave({ ...parsed, settings: settingsRaw });
  }, [form, onSave, messageApi, t]);

  return (
    <Modal
      open={values !== null}
      onCancel={onClose}
      onOk={onSubmit}
      okText={t('save')}
      cancelText={t('cancel')}
      title={t('pages.vpnOutbounds.tunnelModal')}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" initialValues={values ?? undefined}>
        <Form.Item
          name="tag"
          label="Tag"
          rules={[
            { required: true, message: t('pages.vpnOutbounds.toasts.tagRequired') },
            {
              validator: (_, value: string) =>
                !value || existingTags.filter((tag) => tag === value).length <= 1
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('pages.vpnOutbounds.toasts.tagExists'))),
            },
          ]}
        >
          <Input disabled={Boolean(values?.tag && existingTags.includes(values.tag))} />
        </Form.Item>
        <Form.Item name="kind" label={t('pages.vpnOutbounds.kind')} rules={[{ required: true }]}>
          <Select options={kindOptions} placeholder={t('pages.vpnOutbounds.pickKind')} />
        </Form.Item>
        <Form.Item name="remark" label={t('remark')}>
          <Input />
        </Form.Item>
        <Form.Item name="via" label={t('pages.vpnOutbounds.via')}>
          <Select
            allowClear
            options={existingTags.map((tag) => ({ value: tag, label: tag }))}
            placeholder={t('pages.vpnOutbounds.viaHint')}
          />
        </Form.Item>
        <Form.Item name="enable" label={t('enable')} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item
          name="settings"
          label={t('pages.vpnOutbounds.settingsJson')}
          tooltip={t('pages.vpnOutbounds.settingsHint')}
        >
          <Input.TextArea rows={6} placeholder='{"endpoint": "..."}' />
        </Form.Item>
      </Form>
    </Modal>
  );
}

function SshTunnelModal({
  values,
  onClose,
  onSave,
}: {
  values: SshTunnelFormValues | null;
  onClose: () => void;
  onSave: (values: SshTunnelFormValues) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [form] = Form.useForm<SshTunnelFormValues>();
  useEffect(() => {
    if (values) form.setFieldsValue(values);
  }, [values, form]);

  return (
    <Modal
      open={values !== null}
      onCancel={onClose}
      onOk={async () => {
        const parsed = await form.validateFields();
        await onSave(parsed);
      }}
      okText={t('save')}
      cancelText={t('cancel')}
      title={t('pages.vpnOutbounds.sshModal')}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" initialValues={values ?? undefined}>
        <Form.Item name="tag" label="Tag" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="remark" label={t('remark')}>
          <Input />
        </Form.Item>
        <Space size="middle" wrap>
          <Form.Item
            name="address"
            label={t('pages.vpnOutbounds.address')}
            rules={[{ required: true }]}
          >
            <Input style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="port" label={t('pages.vpnProtocols.port')} rules={[{ required: true }]}>
            <InputNumber min={1} max={65535} />
          </Form.Item>
          <Form.Item
            name="username"
            label={t('pages.vpnOutbounds.username')}
            rules={[{ required: true }]}
          >
            <Input style={{ width: 160 }} />
          </Form.Item>
        </Space>
        <Form.Item
          name="authType"
          label={t('pages.vpnOutbounds.authType')}
          rules={[{ required: true }]}
        >
          <Select
            options={[
              { value: 'password', label: t('password') },
              { value: 'privateKey', label: t('pages.vpnOutbounds.privateKey') },
            ]}
          />
        </Form.Item>
        <Form.Item noStyle shouldUpdate={(prev, next) => prev.authType !== next.authType}>
          {({ getFieldValue }) =>
            getFieldValue('authType') === 'privateKey' ? (
              <>
                <Form.Item name="privateKey" label={t('pages.vpnOutbounds.privateKey')}>
                  <Input.TextArea rows={5} />
                </Form.Item>
                <Form.Item name="passphrase" label={t('pages.vpnOutbounds.passphrase')}>
                  <Input.Password />
                </Form.Item>
              </>
            ) : (
              <Form.Item name="password" label={t('password')}>
                <Input.Password />
              </Form.Item>
            )
          }
        </Form.Item>
        <Form.Item
          name="knownHost"
          label={t('pages.vpnOutbounds.knownHost')}
          tooltip={t('pages.vpnOutbounds.knownHostHint')}
        >
          <Input />
        </Form.Item>
      </Form>
    </Modal>
  );
}
