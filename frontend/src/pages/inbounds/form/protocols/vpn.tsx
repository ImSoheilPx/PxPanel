import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, InputNumber, Space, Switch, message } from 'antd';
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons';
import { useFormContext, useFieldArray } from 'react-hook-form';

import type { VpnProtocol } from '@/schemas/api/vpn';
import { useVpnIkev2RemoteId, useVpnProtocolMutations } from '@/api/queries/useVpnProtocols';
import { downloadText } from '@/lib/download';
import { FormField } from '@/components/form/rhf';

/*
 * Per-protocol fields for the vpn-protocol inbounds (l2tp, pptp, openvpn, ...),
 * rendered inside the standard InboundFormModal's Protocol tab. The values live
 * on the form's loose `settings` object — the vpn backend stores them in the
 * same inbounds row's settings JSON, so no extra form state is needed. Every
 * field carries a tooltip: these controls (junk packets, FoU, PSKs, ...) are
 * opaque to anyone who has not run the underlying daemons before.
 */

type FieldKind = 'text' | 'number' | 'bool' | 'password';

interface FieldDef {
  key: string;
  kind: FieldKind;
  min?: number;
  max?: number;
}

const COMMON_FIELDS: FieldDef[] = [
  { key: 'dns1', kind: 'text' },
  { key: 'dns2', kind: 'text' },
  { key: 'mtu', kind: 'number', min: 1000, max: 1500 },
  { key: 'userLimit', kind: 'number', min: 0 },
  { key: 'clientToClient', kind: 'bool' },
  { key: 'crossInbound', kind: 'bool' },
  { key: 'externalProxy', kind: 'bool' },
];

const PROTOCOL_FIELDS: Record<VpnProtocol, FieldDef[]> = {
  l2tp: [
    { key: 'ipsecEnable', kind: 'bool' },
    { key: 'ipsecPsk', kind: 'password' },
    { key: 'allowRaw', kind: 'bool' },
    ...COMMON_FIELDS,
  ],
  pptp: [...COMMON_FIELDS],
  openvpn: [
    { key: 'udpEnable', kind: 'bool' },
    { key: 'tcpEnable', kind: 'bool' },
    { key: 'friendlyName', kind: 'text' },
    { key: 'tlsCryptEnable', kind: 'bool' },
    ...COMMON_FIELDS,
  ],
  openconnect: [{ key: 'tlsUseFile', kind: 'bool' }, ...COMMON_FIELDS],
  sstp: [{ key: 'tlsUseFile', kind: 'bool' }, ...COMMON_FIELDS],
  ikev2: [
    { key: 'authMode', kind: 'text' },
    { key: 'psk', kind: 'password' },
    { key: 'serverAddr', kind: 'text' },
    { key: 'tlsUseFile', kind: 'bool' },
    ...COMMON_FIELDS,
  ],
  'wg-c': [
    { key: 'pskEnable', kind: 'bool' },
    { key: 'serverPubKey', kind: 'text' },
    ...COMMON_FIELDS,
  ],
  awg: [
    { key: 'pskEnable', kind: 'bool' },
    { key: 'serverPubKey', kind: 'text' },
    { key: 'jc', kind: 'number', min: 0 },
    { key: 'jmin', kind: 'number', min: 0 },
    { key: 'jmax', kind: 'number', min: 0 },
    { key: 's1', kind: 'number', min: 0 },
    { key: 's2', kind: 'number', min: 0 },
    { key: 'h1', kind: 'text' },
    { key: 'h2', kind: 'text' },
    { key: 'h3', kind: 'text' },
    { key: 'h4', kind: 'text' },
    ...COMMON_FIELDS,
  ],
  gre: [
    { key: 'ttl', kind: 'number', min: 1, max: 255 },
    { key: 'fouEnable', kind: 'bool' },
    { key: 'fouPort', kind: 'number', min: 0, max: 65535 },
    { key: 'ipsecEnable', kind: 'bool' },
    { key: 'ipsecPsk', kind: 'password' },
    { key: 'allowRaw', kind: 'bool' },
    ...COMMON_FIELDS,
  ],
  ssh: [
    { key: 'externalProxy', kind: 'bool' },
    { key: 'userLimit', kind: 'number', min: 0 },
  ],
};

const CERT_PATHS: Partial<Record<VpnProtocol, string>> = {
  openvpn: 'generate-openvpn-certs',
  openconnect: 'generate-ocserv-cert',
  sstp: 'generate-sstp-cert',
  ikev2: 'generate-ikev2-cert',
};

export interface VpnProtocolFieldsProps {
  protocol: VpnProtocol;
  /** Saved inbound id, or null while adding (cert generation then posts unscoped). */
  inboundId: number | null;
}

export default function VpnProtocolFields({ protocol, inboundId }: VpnProtocolFieldsProps) {
  const { t } = useTranslation();
  const [messageApi, messageContextHolder] = message.useMessage();
  const { control, getValues, setValue } = useFormContext();
  const { generateCert, checkIkev2Cert } = useVpnProtocolMutations();
  const [certBusy, setCertBusy] = useState(false);
  const [certWarning, setCertWarning] = useState('');

  const fields = PROTOCOL_FIELDS[protocol];
  const certKind = CERT_PATHS[protocol];

  const {
    fields: rangeFields,
    append,
    remove,
  } = useFieldArray({
    control,
    name: 'settings.ipRanges',
  });

  const onGenerateCert = useCallback(async () => {
    if (!certKind) return;
    setCertBusy(true);
    try {
      const msg = await generateCert(
        inboundId
          ? `/panel/api/inbounds/${inboundId}/${certKind}`
          : `/panel/api/inbounds/${certKind}`,
      );
      if (!msg?.success || !msg.obj) {
        messageApi.error(msg?.msg || t('somethingWentWrong'));
        return;
      }
      const obj = msg.obj as Record<string, unknown>;
      for (const [key, value] of Object.entries(obj)) {
        setValue(`settings.${key}`, value, { shouldDirty: true });
      }
      if (protocol !== 'openvpn') {
        setValue('settings.tlsUseFile', false, { shouldDirty: true });
      }
      messageApi.success(t('pages.vpnProtocols.toasts.certGenerated'));
    } finally {
      setCertBusy(false);
    }
  }, [certKind, inboundId, generateCert, messageApi, protocol, setValue, t]);

  const onCheckCert = useCallback(async () => {
    const check = await checkIkev2Cert((getValues('settings') ?? {}) as Record<string, unknown>);
    if (!check) {
      messageApi.error(t('somethingWentWrong'));
      return;
    }
    setCertWarning(check.warning || '');
    if (!check.warning) {
      messageApi.success(`${t('pages.vpnProtocols.fields.keyType')}: ${check.keyType}`);
    }
  }, [checkIkev2Cert, getValues, messageApi, t]);

  const onDownloadCertFiles = useCallback(() => {
    const current = (getValues('settings') ?? {}) as Record<string, unknown>;
    const cert = (current.certificate as string) || (current.caCert as string) || '';
    if (!cert) {
      messageApi.info(t('pages.vpnProtocols.noCertYet'));
      return;
    }
    if (current.caCert) downloadText('ca.crt', String(current.caCert), 'application/x-pem-file');
    if (current.certificate)
      downloadText('server.crt', String(current.certificate), 'application/x-pem-file');
    if (current.key) downloadText('server.key', String(current.key), 'application/x-pem-file');
  }, [getValues, messageApi, t]);

  return (
    <>
      {messageContextHolder}
      {protocol !== 'ssh' && (
        <Form.Item
          label={t('pages.vpnProtocols.ipRanges')}
          tooltip={t('pages.vpnProtocols.ipRangesHint')}
        >
          {rangeFields.map((range, index) => (
            <Space key={range.id} style={{ display: 'flex', marginBottom: 8 }}>
              <FormField name={['settings', 'ipRanges', index]} noStyle>
                <Input
                  aria-label={`${t('pages.vpnProtocols.ipRanges')} ${index + 1}`}
                  placeholder="10.0.5.2-10.0.5.254"
                  style={{ width: 280 }}
                />
              </FormField>
              <MinusCircleOutlined
                aria-label={t('remove')}
                onClick={() => remove(index)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') remove(index);
                }}
                role="button"
                tabIndex={0}
              />
            </Space>
          ))}
          <Button size="small" icon={<PlusOutlined aria-hidden />} onClick={() => append('')}>
            {t('add')}
          </Button>
        </Form.Item>
      )}

      {fields.map((field) => (
        <FormField
          key={field.key}
          name={['settings', field.key]}
          label={t(`pages.vpnProtocols.fields.${field.key}`)}
          tooltip={t(`pages.vpnProtocols.fields.${field.key}Hint`)}
          transform={
            field.kind === 'bool'
              ? { input: (value: unknown) => Boolean(value) }
              : field.kind === 'text' || field.kind === 'password'
                ? { input: (value: unknown) => (typeof value === 'string' ? value : '') }
                : {
                    input: (value: unknown) => (typeof value === 'number' ? value : undefined),
                    output: (value: unknown) => (value == null ? 0 : Number(value)),
                  }
          }
          valueProp={field.kind === 'bool' ? 'checked' : 'value'}
        >
          {field.kind === 'bool' ? (
            <Switch />
          ) : field.kind === 'number' ? (
            <InputNumber min={field.min} max={field.max} />
          ) : (
            <Input type={field.kind === 'password' ? 'password' : 'text'} style={{ width: 280 }} />
          )}
        </FormField>
      ))}

      {certKind && (
        <>
          <Form.Item label={t('pages.vpnProtocols.certificate')}>
            <Space wrap>
              <Button loading={certBusy} onClick={onGenerateCert}>
                {t('pages.vpnProtocols.generateCert')}
              </Button>
              <Button onClick={onDownloadCertFiles}>{t('download')}</Button>
              {protocol === 'ikev2' && (
                <Button onClick={onCheckCert}>{t('pages.vpnProtocols.checkCert')}</Button>
              )}
            </Space>
          </Form.Item>
          {certWarning && <Alert type="warning" showIcon message={certWarning} />}
          {protocol === 'ikev2' && inboundId !== null && (
            <Ikev2RemoteIdLine inboundId={inboundId} />
          )}
        </>
      )}
    </>
  );
}

function Ikev2RemoteIdLine({ inboundId }: { inboundId: number }) {
  const { t } = useTranslation();
  const { data } = useVpnIkev2RemoteId(inboundId);
  if (!data?.remoteId) return null;
  return (
    <Form.Item
      label={t('pages.vpnProtocols.remoteId')}
      tooltip={t('pages.vpnProtocols.remoteIdHint')}
      htmlFor="vpn-ikev2-remote-id"
    >
      <Input id="vpn-ikev2-remote-id" value={data.remoteId} readOnly style={{ width: 280 }} />
    </Form.Item>
  );
}
