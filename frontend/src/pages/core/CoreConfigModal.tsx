import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Modal, Select, Space, Spin, message } from 'antd';

import type { CoreConfigTarget } from '@/schemas/api/vpn';
import { useVpnCoreConfig, useVpnCoreMutations } from '@/api/queries/useVpnCore';

interface Props {
  core: string | null;
  onClose: () => void;
}

// The per-core config editor (super-admin gated server-side): the GET names
// every generated file the core writes with its current text, the POST stores an
// override by inbound + file NAME and restarts the core, answering with fresh
// logs and the refreshed target list.
export default function CoreConfigModal({ core, onClose }: Props) {
  const { t } = useTranslation();
  const [messageApi] = message.useMessage();
  const query = useVpnCoreConfig(core);
  const { saveConfig } = useVpnCoreMutations();

  const targets = useMemo(() => query.data?.targets ?? [], [query.data]);
  const [selected, setSelected] = useState('');
  const [saving, setSaving] = useState(false);
  const [health, setHealth] = useState<string>('');
  // The in-flight editor buffer, tagged with the target it was typed against.
  const [edit, setEdit] = useState<{ label: string; text: string } | null>(null);

  // Both derived during render instead of synced by effects: the stored label
  // falls back to the first target when it no longer exists, and the textarea
  // shows the fetched config until the user types against the current target.
  const selectedLabel = targets.some((target) => targetLabel(target) === selected)
    ? selected
    : targets[0]
      ? targetLabel(targets[0])
      : '';
  const current = targets.find((target) => targetLabel(target) === selectedLabel);
  const text = edit && edit.label === selectedLabel ? edit.text : (current?.Text ?? '');
  const setText = (value: string) => setEdit({ label: selectedLabel, text: value });

  const onSave = useCallback(async () => {
    if (!core || !current) return;
    setSaving(true);
    try {
      const result = await saveConfig(core, current.InboundId ?? 0, current.File ?? '', text);
      if (result) {
        const ok = result.health?.ok ?? false;
        if (ok) {
          messageApi.success(t('pages.core.toasts.configSaved'));
        } else {
          messageApi.warning(t('pages.core.configRestartFailed'));
        }
        setHealth(result.health?.logs ?? '');
      } else {
        messageApi.error(t('somethingWentWrong'));
      }
    } finally {
      setSaving(false);
    }
  }, [core, current, text, saveConfig, messageApi, t]);

  return (
    <Modal
      open={core !== null}
      onCancel={onClose}
      footer={[
        <Button key="reload" onClick={() => void query.refetch()}>
          {t('refresh')}
        </Button>,
        <Button key="save" type="primary" loading={saving} disabled={!current} onClick={onSave}>
          {t('save')}
        </Button>,
      ]}
      title={t('pages.core.configTitle', { core: core || '' })}
      width={960}
    >
      <Spin spinning={query.isFetching} aria-live="off">
        {targets.length === 0 && !query.isFetching ? (
          <Alert type="info" showIcon message={t('pages.core.noConfigTargets')} />
        ) : (
          <>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <Select
                style={{ width: '100%' }}
                value={selectedLabel || undefined}
                onChange={setSelected}
                aria-label={t('pages.core.config')}
                options={targets.map((target) => ({
                  value: targetLabel(target),
                  label: targetDisplay(target),
                }))}
              />
              <textarea
                value={text}
                onChange={(event) => setText(event.target.value)}
                spellCheck={false}
                style={{
                  width: '100%',
                  minHeight: 360,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  whiteSpace: 'pre',
                  tabSize: 4,
                }}
              />
              {current && (
                <Alert
                  type="info"
                  showIcon
                  message={`${t('pages.core.configMode')}: replace`}
                  description={t('pages.core.configModeHint')}
                />
              )}
              {health && (
                <pre style={{ maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                  {health}
                </pre>
              )}
            </Space>
          </>
        )}
      </Spin>
    </Modal>
  );
}

function targetLabel(target: CoreConfigTarget): string {
  return `${target.InboundId ?? 0}:${target.File ?? ''}`;
}

function targetDisplay(target: CoreConfigTarget): string {
  const owner = target.InboundId ? `${target.Remark || `#${target.InboundId}`} · ` : '';
  const name = target.Label || target.File;
  return `${owner}${name} (${target.Path})`;
}
