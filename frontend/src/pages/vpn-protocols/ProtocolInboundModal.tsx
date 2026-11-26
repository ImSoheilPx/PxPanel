import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Space,
  Switch,
  message,
} from 'antd';
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons';

import type { VpnProtocol } from '@/schemas/api/vpn';
import {
  useVpnIkev2RemoteId,
  useVpnProtocolMutations,
  type VpnInboundRow,
} from '@/api/queries/useVpnProtocols';
import { downloadText } from '@/lib/download';

interface SettingsFormState {
  [key: string]: unknown;
}

type FieldKind = 'text' | 'number' | 'bool' | 'ranges' | 'password';

interface FieldDef {
  key: string;
  kind: FieldKind;
  labelKey: string;
  min?: number;
  max?: number;
}

const COMMON_FIELDS: FieldDef[] = [
  { key: 'dns1', kind: 'text', labelKey: 'pages.vpnProtocols.fields.dns1' },
  { key: 'dns2', kind: 'text', labelKey: 'pages.vpnProtocols.fields.dns2' },
  { key: 'mtu', kind: 'number', labelKey: 'pages.vpnProtocols.fields.mtu', min: 1000, max: 1500 },
  { key: 'userLimit', kind: 'number', labelKey: 'pages.vpnProtocols.fields.userLimit', min: 0 },
  { key: 'clientToClient', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.clientToClient' },
  { key: 'crossInbound', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.crossInbound' },
  { key: 'externalProxy', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.externalProxy' },
];

const PROTOCOL_FIELDS: Record<VpnProtocol, FieldDef[]> = {
  l2tp: [
    { key: 'ipsecEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.ipsecEnable' },
    { key: 'ipsecPsk', kind: 'password', labelKey: 'pages.vpnProtocols.fields.ipsecPsk' },
    { key: 'allowRaw', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.allowRaw' },
    ...COMMON_FIELDS,
  ],
  pptp: [...COMMON_FIELDS],
  openvpn: [
    { key: 'udpEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.udpEnable' },
    { key: 'tcpEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.tcpEnable' },
    { key: 'friendlyName', kind: 'text', labelKey: 'pages.vpnProtocols.fields.friendlyName' },
    { key: 'tlsCryptEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.tlsCryptEnable' },
    ...COMMON_FIELDS,
  ],
  openconnect: [
    { key: 'tlsUseFile', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.tlsUseFile' },
    ...COMMON_FIELDS,
  ],
  sstp: [
    { key: 'tlsUseFile', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.tlsUseFile' },
    ...COMMON_FIELDS,
  ],
  ikev2: [
    { key: 'authMode', kind: 'text', labelKey: 'pages.vpnProtocols.fields.authMode' },
    { key: 'psk', kind: 'password', labelKey: 'pages.vpnProtocols.fields.psk' },
    { key: 'serverAddr', kind: 'text', labelKey: 'pages.vpnProtocols.fields.serverAddr' },
    { key: 'tlsUseFile', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.tlsUseFile' },
    ...COMMON_FIELDS,
  ],
  'wg-c': [
    { key: 'pskEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.pskEnable' },
    { key: 'serverPubKey', kind: 'text', labelKey: 'pages.vpnProtocols.fields.serverPubKey' },
    ...COMMON_FIELDS,
  ],
  awg: [
    { key: 'pskEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.pskEnable' },
    { key: 'serverPubKey', kind: 'text', labelKey: 'pages.vpnProtocols.fields.serverPubKey' },
    { key: 'jc', kind: 'number', labelKey: 'pages.vpnProtocols.fields.jc', min: 0 },
    { key: 'jmin', kind: 'number', labelKey: 'pages.vpnProtocols.fields.jmin', min: 0 },
    { key: 'jmax', kind: 'number', labelKey: 'pages.vpnProtocols.fields.jmax', min: 0 },
    { key: 's1', kind: 'number', labelKey: 'pages.vpnProtocols.fields.s1', min: 0 },
    { key: 's2', kind: 'number', labelKey: 'pages.vpnProtocols.fields.s2', min: 0 },
    { key: 'h1', kind: 'text', labelKey: 'pages.vpnProtocols.fields.h1' },
    { key: 'h2', kind: 'text', labelKey: 'pages.vpnProtocols.fields.h2' },
    { key: 'h3', kind: 'text', labelKey: 'pages.vpnProtocols.fields.h3' },
    { key: 'h4', kind: 'text', labelKey: 'pages.vpnProtocols.fields.h4' },
    ...COMMON_FIELDS,
  ],
  gre: [
    { key: 'ttl', kind: 'number', labelKey: 'pages.vpnProtocols.fields.ttl', min: 1, max: 255 },
    { key: 'fouEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.fouEnable' },
    {
      key: 'fouPort',
      kind: 'number',
      labelKey: 'pages.vpnProtocols.fields.fouPort',
      min: 0,
      max: 65535,
    },
    { key: 'ipsecEnable', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.ipsecEnable' },
    { key: 'ipsecPsk', kind: 'password', labelKey: 'pages.vpnProtocols.fields.ipsecPsk' },
    { key: 'allowRaw', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.allowRaw' },
    ...COMMON_FIELDS,
  ],
  ssh: [
    { key: 'externalProxy', kind: 'bool', labelKey: 'pages.vpnProtocols.fields.externalProxy' },
    { key: 'userLimit', kind: 'number', labelKey: 'pages.vpnProtocols.fields.userLimit', min: 0 },
  ],
};

const CERT_PATHS: Partial<Record<VpnProtocol, string>> = {
  openvpn: 'generate-openvpn-certs',
  openconnect: 'generate-ocserv-cert',
  sstp: 'generate-sstp-cert',
  ikev2: 'generate-ikev2-cert',
};

interface Props {
  open: boolean;
  protocol: VpnProtocol;
  inbound: VpnInboundRow | null;
  onClose: () => void;
}

export default function ProtocolInboundModal({ open, protocol, inbound, onClose }: Props) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const { saveInbound, updateInbound, generateCert, checkIkev2Cert } = useVpnProtocolMutations();
  const editingId = inbound?.id ?? 0;

  const [remark, setRemark] = useState('');
  const [port, setPort] = useState<number>(0);
  const [listen, setListen] = useState('');
  const [enable, setEnable] = useState(true);
  const [settings, setSettings] = useState<SettingsFormState>({});
  const [saving, setSaving] = useState(false);
  const [certWarning, setCertWarning] = useState('');

  // Seed from the inbound (or per-protocol defaults) each time the modal opens.
  useEffect(() => {
    if (!open) return;
    setCertWarning('');
    setRemark(inbound?.remark ?? '');
    setPort(inbound?.port ?? 0);
    setListen(inbound?.listen ?? '');
    setEnable(inbound?.enable ?? true);
    setSettings(inbound ? { ...inbound.settings } : {});
  }, [open, inbound]);

  const fields = PROTOCOL_FIELDS[protocol];
  const certKind = CERT_PATHS[protocol];

  const ranges = useMemo(
    () => (settings.ipRanges as string[] | undefined) ?? [],
    [settings],
  );

  const setField = useCallback((key: string, value: unknown) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }, []);

  const onGenerateCert = useCallback(async () => {
    if (!certKind) return;
    const msg = await generateCert(
      editingId > 0
        ? `/panel/api/inbounds/${editingId}/${certKind}`
        : `/panel/api/inbounds/${certKind}`,
    );
    if (!msg?.success || !msg.obj) {
      messageApi.error(msg?.msg || t('somethingWentWrong'));
      return;
    }
    const obj = msg.obj as Record<string, unknown>;
    setSettings((prev) => {
      const next = { ...prev, ...obj };
      if (protocol !== 'openvpn') next.tlsUseFile = false;
      return next;
    });
    messageApi.success(t('pages.vpnProtocols.toasts.certGenerated'));
  }, [certKind, editingId, generateCert, messageApi, protocol, t]);

  const onCheckCert = useCallback(async () => {
    const check = await checkIkev2Cert(settings);
    if (!check) {
      messageApi.error(t('somethingWentWrong'));
      return;
    }
    setCertWarning(check.warning || '');
    if (!check.warning)
      messageApi.success(`${t('pages.vpnProtocols.fields.keyType')}: ${check.keyType}`);
  }, [checkIkev2Cert, settings, messageApi, t]);

  const onDownloadCertFiles = useCallback(() => {
    const cert = (settings.certificate as string) || (settings.caCert as string) || '';
    if (!cert) {
      messageApi.info(t('pages.vpnProtocols.noCertYet'));
      return;
    }
    if (settings.caCert) downloadText('ca.crt', String(settings.caCert), 'application/x-pem-file');
    if (settings.certificate)
      downloadText('server.crt', String(settings.certificate), 'application/x-pem-file');
    if (settings.key) downloadText('server.key', String(settings.key), 'application/x-pem-file');
  }, [settings, messageApi, t]);

  const onSave = useCallback(async () => {
    if (!remark.trim()) {
      messageApi.error(t('pages.vpnProtocols.toasts.remarkRequired'));
      return;
    }
    if (port < 1 || port > 65535) {
      messageApi.error(t('pages.vpnProtocols.toasts.portRange'));
      return;
    }
    setSaving(true);
    try {
      const base: Record<string, unknown> = inbound
        ? { ...inbound.settings }
        : { clients: [] };
      const payload: Record<string, unknown> = {
        id: editingId,
        enable,
        remark: remark.trim(),
        listen,
        port,
        protocol,
        expiryTime: 0,
        total: 0,
        settings: { ...base, ...settings, ipRanges: ranges.filter((r) => r.trim() !== '') },
      };
      const msg =
        editingId > 0 ? await updateInbound(editingId, payload) : await saveInbound(payload);
      if (msg?.success) {
        messageApi.success(t('pages.vpnProtocols.toasts.saved'));
        onClose();
      } else {
        messageApi.error(msg?.msg || t('somethingWentWrong'));
      }
    } finally {
      setSaving(false);
    }
  }, [
    inbound,
    editingId,
    enable,
    remark,
    listen,
    port,
    protocol,
    settings,
    ranges,
    saveInbound,
    updateInbound,
    onClose,
    messageApi,
    t,
  ]);

  return (
    <Modal
      open={open}
      title={
        `${inbound ? t('pages.vpnProtocols.editInbound') : t('pages.vpnProtocols.addInbound')} — ` +
        t(`pages.vpnProtocols.protocolNames.${protocol}`)
      }
      onCancel={onClose}
      width={720}
      footer={[
        <Button key="cancel" onClick={onClose}>
          {t('cancel')}
        </Button>,
        <Button key="save" type="primary" loading={saving} onClick={onSave}>
          {t('save')}
        </Button>,
      ]}
    >
      <Form layout="vertical">
        <Space size="middle" wrap>
          <Form.Item label={t('remark')} required>
            <Input
              value={remark}
              onChange={(e) => setRemark(e.target.value)}
              style={{ width: 220 }}
            />
          </Form.Item>
          <Form.Item label={t('pages.vpnProtocols.port')} required>
            <InputNumber min={1} max={65535} value={port} onChange={(v) => setPort(v ?? 0)} />
          </Form.Item>
          <Form.Item label={t('pages.vpnProtocols.listen')}>
            <Input
              value={listen}
              onChange={(e) => setListen(e.target.value)}
              style={{ width: 160 }}
            />
          </Form.Item>
          <Form.Item label={t('enable')}>
            <Switch checked={enable} onChange={setEnable} />
          </Form.Item>
        </Space>

        {protocol !== 'ssh' && (
          <Form.Item
            label={t('pages.vpnProtocols.ipRanges')}
            tooltip={t('pages.vpnProtocols.ipRangesHint')}
          >
            {ranges.map((range, index) => (
              <Space key={index} style={{ display: 'flex', marginBottom: 8 }}>
                <Input
                  value={range}
                  placeholder="10.0.5.2-10.0.5.254"
                  style={{ width: 280 }}
                  onChange={(e) => {
                    const next = [...ranges];
                    next[index] = e.target.value;
                    setField('ipRanges', next);
                  }}
                />
                <MinusCircleOutlined
                  onClick={() => setField('ipRanges', ranges.filter((_, i) => i !== index))}
                />
              </Space>
            ))}
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() => setField('ipRanges', [...ranges, ''])}
            >
              {t('add')}
            </Button>
          </Form.Item>
        )}

        {fields.map((field) => (
          <Form.Item key={field.key} label={t(field.labelKey)}>
            {field.kind === 'bool' ? (
              <Switch
                checked={Boolean(settings[field.key])}
                onChange={(v) => setField(field.key, v)}
              />
            ) : field.kind === 'number' ? (
              <InputNumber
                min={field.min}
                max={field.max}
                value={(settings[field.key] as number | undefined) ?? undefined}
                onChange={(v) => setField(field.key, v ?? 0)}
              />
            ) : (
              <Input
                type={field.kind === 'password' ? 'password' : 'text'}
                value={(settings[field.key] as string | undefined) ?? ''}
                style={{ width: 280 }}
                onChange={(e) => setField(field.key, e.target.value)}
              />
            )}
          </Form.Item>
        ))}

        {certKind && (
          <>
            <Form.Item label={t('pages.vpnProtocols.certificate')}>
              <Space wrap>
                <Button onClick={onGenerateCert}>{t('pages.vpnProtocols.generateCert')}</Button>
                <Button onClick={onDownloadCertFiles}>{t('download')}</Button>
                {protocol === 'ikev2' && (
                  <Button onClick={onCheckCert}>{t('pages.vpnProtocols.checkCert')}</Button>
                )}
              </Space>
            </Form.Item>
            {certWarning && <Alert type="warning" showIcon message={certWarning} />}
            {protocol === 'ikev2' && editingId > 0 && <Ikev2RemoteIdLine inboundId={editingId} />}
          </>
        )}
      </Form>
    </Modal>
  );
}

function Ikev2RemoteIdLine({ inboundId }: { inboundId: number }) {
  const { t } = useTranslation();
  const { data } = useVpnIkev2RemoteId(inboundId);
  if (!data?.remoteId) return null;
  return (
    <Form.Item label={t('pages.vpnProtocols.remoteId')}>
      <Input value={data.remoteId} readOnly style={{ width: 280 }} />
    </Form.Item>
  );
}
