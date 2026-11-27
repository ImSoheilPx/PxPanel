import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Button,
  Card,
  Col,
  ConfigProvider,
  Form,
  Input,
  Layout,
  Modal,
  Result,
  Row,
  Select,
  Space,
  Spin,
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
import { selectTagRender } from '@/components/form';
import type { AdminRow, InboundBrief, PermissionSlug } from '@/schemas/api/vpn';
import {
  useVpnAdminInboundsQuery,
  useVpnAdminMutations,
  useVpnAdminsQuery,
  useVpnPermissionsQuery,
  type AdminFormValues,
} from '@/api/queries/useVpnAdmins';

function inboundOptionLabel(option: InboundBrief): string {
  const name = option.remark || `#${option.id}`;
  return `${name} (${option.protocol}:${option.port})`;
}

export default function AdminsPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { isMobile } = useMediaQuery();
  const [modal, modalContextHolder] = Modal.useModal();
  const [messageApi, messageContextHolder] = message.useMessage();
  useEffect(() => {
    setMessageInstance(messageApi);
  }, [messageApi]);

  const { admins, loading, fetched, fetchError, refetch } = useVpnAdminsQuery();
  const permissions = useVpnPermissionsQuery() as PermissionSlug[];
  const inboundOptions = useVpnAdminInboundsQuery() as InboundBrief[];
  const { add, update, remove, reassign } = useVpnAdminMutations();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<AdminRow | null>(null);
  const [reassignOpen, setReassignOpen] = useState(false);
  const [reassignFrom, setReassignFrom] = useState<number | null>(null);
  const [reassignTo, setReassignTo] = useState<number | null>(null);

  const onAdd = useCallback(() => {
    setEditing(null);
    setFormOpen(true);
  }, []);

  const onEdit = useCallback((admin: AdminRow) => {
    setEditing(admin);
    setFormOpen(true);
  }, []);

  const onDelete = useCallback(
    (admin: AdminRow) => {
      modal.confirm({
        title: t('pages.admins.deleteConfirm', { name: admin.username }),
        okText: t('delete'),
        okType: 'danger',
        cancelText: t('cancel'),
        onOk: async () => {
          const msg = await remove(admin.id);
          if (msg?.success) messageApi.success(t('pages.admins.toasts.deleted'));
          else messageApi.error(msg?.msg || t('somethingWentWrong'));
        },
      });
    },
    [modal, remove, messageApi, t],
  );

  const onReassign = useCallback(async () => {
    if (reassignFrom === null || reassignTo === null || reassignFrom === reassignTo) return;
    const moved = await reassign(reassignFrom, reassignTo);
    if (moved !== null) {
      messageApi.success(t('pages.admins.toasts.reassigned', { count: moved }));
      setReassignOpen(false);
    } else {
      messageApi.error(t('somethingWentWrong'));
    }
  }, [reassignFrom, reassignTo, reassign, messageApi, t]);

  const columns: ColumnsType<AdminRow> = [
    {
      title: t('pages.admins.username'),
      dataIndex: 'username',
      render: (_, row) => (
        <Space>
          <span>{row.username}</span>
          {row.isSuperAdmin && <Tag color="gold">{t('pages.admins.superAdmin')}</Tag>}
          {!row.enable && <Tag>{t('disabled')}</Tag>}
          {row.twoFactorEnable && <Tag color="blue">2FA</Tag>}
        </Space>
      ),
    },
    { title: t('pages.resellers.nickname'), dataIndex: 'nickname' },
    {
      title: t('pages.admins.permissions'),
      dataIndex: 'permissions',
      render: (_, row) =>
        row.isSuperAdmin ? (
          '—'
        ) : (
          <Space wrap size={4}>
            {row.permissions.map((slug) => (
              <Tag key={slug}>{slug}</Tag>
            ))}
            {row.permissions.length === 0 && '—'}
          </Space>
        ),
    },
    {
      title: t('pages.admins.inboundCount'),
      dataIndex: 'inboundCount',
      render: (count) => count || '—',
    },
    {
      title: '',
      render: (_, row) => (
        <Space>
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
    const classes = ['admins-page'];
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
                    <Card
                      size="small"
                      title={t('pages.admins.title')}
                      extra={
                        <Space>
                          <Button onClick={() => setReassignOpen(true)}>
                            {t('pages.admins.reassign')}
                          </Button>
                          <Button onClick={() => refetch()}>{t('refresh')}</Button>
                          <Button type="primary" onClick={onAdd}>
                            {t('pages.admins.add')}
                          </Button>
                        </Space>
                      }
                    >
                      <Table<AdminRow>
                        rowKey="id"
                        size="small"
                        loading={loading}
                        columns={columns}
                        dataSource={admins}
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

        <AdminFormModal
          open={formOpen}
          admin={editing}
          permissions={permissions}
          inboundOptions={inboundOptions}
          onClose={() => setFormOpen(false)}
          onSave={async (values) => {
            const msg = editing ? await update(editing.id, values) : await add(values);
            if (msg?.success) {
              messageApi.success(
                editing ? t('pages.admins.toasts.updated') : t('pages.admins.toasts.added'),
              );
              setFormOpen(false);
            } else {
              messageApi.error(msg?.msg || t('somethingWentWrong'));
            }
          }}
        />

        <Modal
          open={reassignOpen}
          title={t('pages.admins.reassign')}
          onCancel={() => setReassignOpen(false)}
          onOk={onReassign}
          okText={t('pages.admins.reassign')}
          cancelText={t('cancel')}
        >
          <Space direction="vertical" style={{ width: '100%' }} size="middle">
            <Select
              style={{ width: '100%' }}
              placeholder={t('pages.admins.reassignFrom')}
              aria-label={t('pages.admins.reassignFrom')}
              value={reassignFrom}
              onChange={setReassignFrom}
              options={admins.map((admin) => ({
                value: admin.id,
                label: `${admin.username} (${admin.inboundCount})`,
              }))}
            />
            <Select
              style={{ width: '100%' }}
              placeholder={t('pages.admins.reassignTo')}
              aria-label={t('pages.admins.reassignTo')}
              value={reassignTo}
              onChange={setReassignTo}
              options={admins.map((admin) => ({
                value: admin.id,
                label: admin.username,
              }))}
            />
          </Space>
        </Modal>
      </Layout>
    </ConfigProvider>
  );
}

function AdminFormModal({
  open,
  admin,
  permissions,
  inboundOptions,
  onClose,
  onSave,
}: {
  open: boolean;
  admin: AdminRow | null;
  permissions: PermissionSlug[];
  inboundOptions: InboundBrief[];
  onClose: () => void;
  onSave: (values: AdminFormValues) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [form] = Form.useForm<AdminFormValues>();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (admin) {
      form.setFieldsValue({
        username: admin.username,
        password: '',
        nickname: admin.nickname,
        enable: admin.enable,
        isSuperAdmin: admin.isSuperAdmin,
        permissions: admin.permissions,
        inboundIds: admin.inboundIds,
      });
    } else {
      form.resetFields();
    }
  }, [open, admin, form]);

  return (
    <Modal
      open={open}
      title={admin ? t('pages.admins.edit') : t('pages.admins.add')}
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
          isSuperAdmin: false,
          permissions: [],
          inboundIds: [],
        }}
      >
        <Space size="middle" wrap>
          <Form.Item
            name="username"
            label={t('pages.admins.username')}
            rules={[{ required: true }]}
          >
            <Input style={{ width: 200 }} />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('password')}
            extra={admin ? t('pages.admins.passwordKeepHint') : undefined}
            rules={admin ? [] : [{ required: true }]}
          >
            <Input.Password style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="nickname" label={t('pages.resellers.nickname')}>
            <Input style={{ width: 160 }} />
          </Form.Item>
          <Form.Item name="enable" label={t('enable')} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item
            name="isSuperAdmin"
            label={t('pages.admins.superAdmin')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Space>
        <Form.Item noStyle shouldUpdate={(prev, next) => prev.isSuperAdmin !== next.isSuperAdmin}>
          {({ getFieldValue }) =>
            !getFieldValue('isSuperAdmin') && (
              <>
                <Form.Item
                  name="permissions"
                  label={t('pages.admins.permissions')}
                  tooltip={t('pages.admins.permissionsHint')}
                >
                  <Select
                    mode="multiple"
                    allowClear
                    tagRender={selectTagRender}
                    options={permissions.map((permission) => ({
                      value: permission.slug,
                      label: permission.slug,
                    }))}
                  />
                </Form.Item>
                <Form.Item name="inboundIds" label={t('pages.admins.inboundAccess')}>
                  <Select
                    mode="multiple"
                    allowClear
                    tagRender={selectTagRender}
                    options={inboundOptions.map((option) => ({
                      value: option.id,
                      label: inboundOptionLabel(option),
                    }))}
                  />
                </Form.Item>
              </>
            )
          }
        </Form.Item>
      </Form>
    </Modal>
  );
}
