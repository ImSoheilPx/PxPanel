import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Form,
  Modal,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tag,
  message,
} from 'antd';

import { selectTagRender } from '@/components/form';
import type { AccountRow, BulkPreview } from '@/schemas/api/vpn';
import {
  useVpnAccountMutations,
  useVpnAccounts,
  useVpnAssignableInbounds,
} from '@/api/queries/useVpnAccounts';

interface Props {
  open: boolean;
  onClose: () => void;
}

const GB = 1024 * 1024 * 1024;

// The quote/charge bulk flow: pick a membership op + targets, price it with
// bulkPreview (writes nothing), then apply it with bulkMembership. The preview
// tells a reseller what they can afford before anything moves.
export default function ResellerBulkModal({ open, onClose }: Props) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const [form] = Form.useForm<{
    op: 'addInbounds' | 'removeInbounds';
    inboundIds: number[];
    emails: string[];
  }>();

  const accounts = useVpnAccounts({ page: 1, size: 200 });
  const assignable = useVpnAssignableInbounds();
  const { previewBulk, applyBulk } = useVpnAccountMutations();

  const [preview, setPreview] = useState<BulkPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [applying, setApplying] = useState(false);

  const emailOptions = (accounts.data?.rows ?? []).map((row: AccountRow) => ({
    value: row.email,
    label: row.email,
  }));

  const targets = useCallback(
    (emails: string[]) =>
      emails.map((email) => {
        const row = (accounts.data?.rows ?? []).find((candidate) => candidate.email === email);
        const membership = row?.memberships[0];
        return { inboundId: membership?.inboundId ?? 0, email };
      }),
    [accounts.data],
  );

  const onPreview = useCallback(async () => {
    const values = await form.validateFields();
    if (values.emails.length === 0 || values.inboundIds.length === 0) return;
    setPreviewing(true);
    try {
      const result = await previewBulk({
        op: values.op,
        inboundIds: values.inboundIds,
        targets: targets(values.emails),
      });
      if (result) setPreview(result);
      else messageApi.error(t('somethingWentWrong'));
    } finally {
      setPreviewing(false);
    }
  }, [form, previewBulk, targets, messageApi, t]);

  const onApply = useCallback(async () => {
    const values = await form.validateFields();
    setApplying(true);
    try {
      const result = await applyBulk({
        op: values.op,
        inboundIds: values.inboundIds,
        targets: targets(values.emails),
      });
      if (result) {
        messageApi.success(
          t('pages.resellers.bulk.applied', { applied: result.applied, skipped: result.skipped }),
        );
        if (result.reasons?.length) {
          messageApi.warning(result.reasons.join(' | '));
        }
        setPreview(null);
        onClose();
      } else {
        messageApi.error(t('somethingWentWrong'));
      }
    } finally {
      setApplying(false);
    }
  }, [form, applyBulk, targets, messageApi, t, onClose]);

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title={t('pages.resellers.bulk.title')}
      width={760}
      footer={[
        <Button key="cancel" onClick={onClose}>
          {t('close')}
        </Button>,
        <Button key="preview" loading={previewing} onClick={onPreview}>
          {t('pages.resellers.bulk.preview')}
        </Button>,
        <Button key="apply" type="primary" loading={applying} disabled={!preview} onClick={onApply}>
          {t('pages.resellers.bulk.apply')}
        </Button>,
      ]}
    >
      <Form
        form={form}
        layout="vertical"
        initialValues={{ op: 'addInbounds', inboundIds: [], emails: [] }}
      >
        <Form.Item
          name="op"
          label={t('pages.resellers.bulk.op')}
          tooltip={t('pages.resellers.bulk.opHint')}
          rules={[{ required: true }]}
        >
          <Select
            options={[
              { value: 'addInbounds', label: t('pages.resellers.bulk.addInbounds') },
              { value: 'removeInbounds', label: t('pages.resellers.bulk.removeInbounds') },
            ]}
          />
        </Form.Item>
        <Form.Item
          name="inboundIds"
          label={t('pages.resellers.bulk.inboundIds')}
          tooltip={t('pages.resellers.bulk.inboundIdsHint')}
          rules={[{ required: true, message: t('pages.resellers.bulk.pickInbound') }]}
        >
          <Select
            mode="multiple"
            allowClear
            tagRender={selectTagRender}
            options={assignable.map((option) => ({
              value: option.id,
              label: `${option.remark || `#${option.id}`} (${option.protocol}:${option.port})`,
            }))}
          />
        </Form.Item>
        <Form.Item
          name="emails"
          label={t('pages.resellers.bulk.targets')}
          tooltip={t('pages.resellers.bulk.targetsHint')}
          rules={[{ required: true, message: t('pages.resellers.bulk.pickTargets') }]}
        >
          <Select
            mode="multiple"
            allowClear
            showSearch
            tagRender={selectTagRender}
            options={emailOptions}
          />
        </Form.Item>
      </Form>

      <Spin spinning={previewing} aria-live="off">
        {preview && (
          <div>
            <Space size="large" wrap style={{ marginBottom: 12 }}>
              <Statistic
                title={t('pages.resellers.bulk.cost')}
                value={`${(preview.costBytes / GB).toFixed(2)} GB`}
              />
              <Statistic
                title={t('pages.resellers.bulk.available')}
                value={`${(preview.availableBytes / GB).toFixed(2)} GB`}
              />
              <Statistic
                title={t('pages.resellers.bulk.eligible')}
                value={`${preview.canProcess} / ${preview.totalTargets}`}
              />
            </Space>
            {!preview.affordable && (
              <Alert
                type="warning"
                showIcon
                message={t('pages.resellers.bulk.notAffordable', {
                  short: (preview.shortBytes / GB).toFixed(2),
                })}
              />
            )}
            <Table
              rowKey="email"
              size="small"
              style={{ marginTop: 12 }}
              pagination={false}
              dataSource={preview.processEmails.map((email) => ({ email }))}
              columns={[
                {
                  title: t('pages.resellers.bulk.willProcess'),
                  dataIndex: 'email',
                  render: (email: string) => <Tag color="green">{email}</Tag>,
                },
              ]}
            />
          </div>
        )}
      </Spin>
    </Modal>
  );
}
