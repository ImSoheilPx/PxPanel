import { useCallback, useEffect, useMemo, useState } from 'react';
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
  Result,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tag,
  message,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useTheme } from '@/hooks/useTheme';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import AppSidebar from '@/layouts/AppSidebar';
import { setMessageInstance } from '@/utils/messageBus';
import type { InboundBrief, ResellerView } from '@/schemas/api/vpn';
import {
  useVpnResellerInboundsQuery,
  useVpnResellerMutations,
  useVpnResellersQuery,
  type ResellerFormValues,
} from '@/api/queries/useVpnResellers';
import { useVpnResellerBalance } from '@/api/queries/useVpnAccounts';
import ResellerBulkModal from './ResellerBulkModal';

const GB = 1024 * 1024 * 1024;

export default function ResellersPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const { resellers, loading, fetched, fetchError, refetch } = useVpnResellersQuery();
  const { add, update, remove, recharge } = useVpnResellerMutations();
  const inboundOptions = useVpnResellerInboundsQuery();
  const balance = useVpnResellerBalance();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ResellerView | null>(null);
  const [recharging, setRecharging] = useState<ResellerView | null>(null);
  const [rechargeGb, setRechargeGb] = useState<number>(0);
  const [bulkOpen, setBulkOpen] = useState(false);

  const onAdd = useCallback(() => {
    setEditing(null);
    setFormOpen(true);
  }, []);

  const onEdit = useCallback((reseller: ResellerView) => {
    setEditing(reseller);
    setFormOpen(true);
  }, []);

  const onRecharge = useCallback(
    async (reseller: ResellerView, gb: number) => {
      const msg = await recharge(reseller.id, gb);
      if (msg?.success) {
        messageApi.success(t('pages.resellers.toasts.recharged'));
        setRecharging(null);
        setRechargeGb(0);
      } else {
        messageApi.error(msg?.msg || t('somethingWentWrong'));
      }
    },
    [recharge, messageApi, t],
  );

  const onDelete = useCallback(
    (reseller: ResellerView) => {
      modal.confirm({
        title: t('pages.resellers.deleteConfirm', { name: reseller.username }),
        content:
          reseller.clientCount > 0
            ? t('pages.resellers.deleteClientsNote', { count: reseller.clientCount })
            : undefined,
        okText: t('delete'),
        okType: 'danger',
        cancelText: t('cancel'),
        onOk: async () => {
          const mode = reseller.clientCount > 0 ? 'keep' : 'cascade';
          if (reseller.clientCount > 0) {
            // Accounts exist: ask explicitly which way they go (the destructive
            // path is never the default).
            modal.confirm({
              title: t('pages.resellers.cascadeTitle'),
              content: t('pages.resellers.cascadeChoice'),
              okText: t('pages.resellers.cascade'),
              okType: 'danger',
              cancelText: t('pages.resellers.keep'),
              onOk: () => remove(reseller.id, 'cascade'),
              onCancel: () => remove(reseller.id, 'keep'),
            });
            return;
          }
          const msg = await remove(reseller.id, mode);
          if (msg?.success) messageApi.success(t('pages.resellers.toasts.deleted'));
          else messageApi.error(msg?.msg || t('somethingWentWrong'));
        },
      });
    },
    [modal, remove, messageApi, t],
  );

  const columns: ColumnsType<ResellerView> = [
    {
      title: t('pages.resellers.username'),
      dataIndex: 'username',
      render: (_, row) => (
        <Space>
          <span>{row.username}</span>
          {row.unlimited && <Tag color="purple">{t('unlimited')}</Tag>}
          {!row.enable && <Tag>{t('disabled')}</Tag>}
        </Space>
      ),
    },
    { title: t('pages.resellers.nickname'), dataIndex: 'nickname' },
    {
      title: t('pages.resellers.available'),
      render: (_, row) =>
        row.unlimited ? t('unlimited') : `${(row.availableBytes / GB).toFixed(1)} GB`,
    },
    {
      title: t('pages.resellers.spent'),
      render: (_, row) => `${(row.spentBytes / GB).toFixed(1)} GB`,
    },
    { title: t('pages.resellers.daysPerGb'), dataIndex: 'daysPerGb' },
    { title: t('clients'), dataIndex: 'clientCount' },
    {
      title: t('pages.resellers.inbounds'),
      render: (_, row) => (
        <Space wrap size={4}>
          {row.inboundIds.map((id) => {
            const brief = inboundOptions.find((option) => option.id === id);
            return (
              <Tag key={id}>{brief ? brief.remark || `#${id}` : `#${id}`}</Tag>
            );
          })}
          {row.inboundIds.length === 0 && '—'}
        </Space>
      ),
    },
    {
      title: '',
      render: (_, row) => (
        <Space>
          <Button size="small" type="link" onClick={() => setRecharging(row)}>
            {t('pages.resellers.recharge')}
          </Button>
          <Button size="small" type="link" onClick={() => onEdit(row)}>
            {t('edit')}
          </Button>
          <Button size="small" type="link" danger onClick={() => onDelete(row)}>
            {t('delete')}
          </Button>
        </Space>
      ),
    },
  ];

  const pageClass = useMemo(() => {
    const classes = ['resellers-page'];
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
                  {balance?.isReseller && (
                    <Col span={24}>
                      <Card size="small" hoverable className="summary-card">
                        <Row gutter={[16, 12]}>
                          <Col xs={8}>
                            <Statistic
                              title={t('pages.resellers.myAvailable')}
                              value={`${(balance.availableBytes / GB).toFixed(1)} GB`}
                            />
                          </Col>
                          <Col xs={8}>
                            <Statistic
                              title={t('pages.resellers.spent')}
                              value={`${(balance.spentBytes / GB).toFixed(1)} GB`}
                            />
                          </Col>
                          <Col xs={8}>
                            <Statistic
                              title={t('pages.resellers.allowance')}
                              value={`${(balance.allowanceBytes / GB).toFixed(1)} GB`}
                            />
                          </Col>
                        </Row>
                      </Card>
                    </Col>
                  )}
                  <Col span={24}>
                    <Card
                      size="small"
                      title={t('pages.resellers.title')}
                      extra={
                        <Space>
                          <Button onClick={() => refetch()}>{t('refresh')}</Button>
                          <Button onClick={() => setBulkOpen(true)}>
                            {t('pages.resellers.bulk.title')}
                          </Button>
                          <Button type="primary" onClick={onAdd}>
                            {t('pages.resellers.add')}
                          </Button>
                        </Space>
                      }
                    >
                      <Table<ResellerView>
                        rowKey="id"
                        size="small"
                        loading={loading}
                        columns={columns}
                        dataSource={resellers}
                        pagination={false}
                        locale={{ emptyText: t('noData') }}
                      />
                    </Card>
                  </Col>
                </Row>
              )}
            </Spin>
          </Layout.Content>
        </Layout>

        <ResellerFormModal
          open={formOpen}
          reseller={editing}
          inboundOptions={inboundOptions}
          onClose={() => setFormOpen(false)}
          onSave={async (values) => {
            const msg = editing ? await update(editing.id, values) : await add(values);
            if (msg?.success) {
              messageApi.success(
                editing
                  ? t('pages.resellers.toasts.updated')
                  : t('pages.resellers.toasts.added'),
              );
              setFormOpen(false);
            } else {
              messageApi.error(msg?.msg || t('somethingWentWrong'));
            }
          }}
        />

        <Modal
          open={recharging !== null}
          title={t('pages.resellers.rechargeTitle', { name: recharging?.username || '' })}
          onCancel={() => setRecharging(null)}
          onOk={() => recharging && onRecharge(recharging, rechargeGb)}
          okText={t('pages.resellers.recharge')}
          cancelText={t('cancel')}
        >
          <InputNumber
            style={{ width: '100%' }}
            value={rechargeGb}
            onChange={(v) => setRechargeGb(v ?? 0)}
            addonAfter="GB"
          />
          <p style={{ marginTop: 8 }}>{t('pages.resellers.rechargeHint')}</p>
        </Modal>

        <ResellerBulkModal open={bulkOpen} onClose={() => setBulkOpen(false)} />
      </Layout>
    </ConfigProvider>
  );
}

export function ResellerFormModal({
  open,
  reseller,
  inboundOptions,
  onClose,
  onSave,
}: {
  open: boolean;
  reseller: ResellerView | null;
  inboundOptions: InboundBrief[];
  onClose: () => void;
  onSave: (values: ResellerFormValues) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [form] = Form.useForm<ResellerFormValues>();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (reseller) {
      form.setFieldsValue({
        username: reseller.username,
        password: '',
        nickname: reseller.nickname,
        enable: reseller.enable,
        unlimited: reseller.unlimited,
        allowanceGb: 0,
        daysPerGb: reseller.daysPerGb,
        minCreateGb: reseller.minCreateGb,
        minAddGb: reseller.minAddGb,
        allowExternalProxy: reseller.allowExternalProxy,
        allowOverview: reseller.allowOverview,
        allowOverviewManage: reseller.allowOverviewManage,
        inboundIds: reseller.inboundIds,
      });
    } else {
      form.resetFields();
    }
  }, [open, reseller, form]);

  return (
    <Modal
      open={open}
      title={reseller ? t('pages.resellers.edit') : t('pages.resellers.add')}
      onCancel={onClose}
      confirmLoading={saving}
      okText={t('save')}
      cancelText={t('cancel')}
      onOk={async () => {
        const values = await form.validateFields();
        setSaving(true);
        try {
          await onSave(values);
        } finally {
          setSaving(false);
        }
      }}
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{
          enable: true,
          unlimited: false,
          allowanceGb: 10,
          daysPerGb: 0,
          minCreateGb: 0,
          minAddGb: 0,
          allowExternalProxy: false,
          allowOverview: false,
          allowOverviewManage: false,
          inboundIds: [],
        }}
      >
        <Space size="middle" wrap>
          <Form.Item
            name="username"
            label={t('pages.resellers.username')}
            rules={[{ required: true }]}
          >
            <Input style={{ width: 200 }} />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('password')}
            extra={reseller ? t('pages.resellers.passwordKeepHint') : undefined}
            rules={reseller ? [] : [{ required: true }]}
          >
            <Input.Password style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="nickname" label={t('pages.resellers.nickname')}>
            <Input style={{ width: 160 }} />
          </Form.Item>
          <Form.Item name="enable" label={t('enable')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
        <Space size="middle" wrap>
          <Form.Item name="unlimited" label={t('unlimited')} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item
            name="allowanceGb"
            label={t('pages.resellers.allowanceGb')}
            extra={reseller ? t('pages.resellers.allowanceIgnoredOnEdit') : undefined}
          >
            <InputNumber min={0} />
          </Form.Item>
          <Form.Item name="daysPerGb" label={t('pages.resellers.daysPerGb')}>
            <InputNumber min={0} />
          </Form.Item>
          <Form.Item name="minCreateGb" label={t('pages.resellers.minCreateGb')}>
            <InputNumber min={0} />
          </Form.Item>
          <Form.Item name="minAddGb" label={t('pages.resellers.minAddGb')}>
            <InputNumber min={0} />
          </Form.Item>
        </Space>
        <Form.Item
          name="allowExternalProxy"
          label={t('pages.resellers.allowExternalProxy')}
          valuePropName="checked"
        >
          <Switch />
        </Form.Item>
        <Space size="middle" wrap>
          <Form.Item
            name="allowOverview"
            label={t('pages.resellers.allowOverview')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="allowOverviewManage"
            label={t('pages.resellers.allowOverviewManage')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Space>
        <Form.Item name="inboundIds" label={t('pages.resellers.inbounds')}>
          <Select
            mode="multiple"
            allowClear
            options={inboundOptions.map((option) => ({
              value: option.id,
              label: `${option.remark || `#${option.id}`} (${option.protocol}:${option.port})`,
            }))}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
