import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi, afterEach } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

import { DBInbound } from '@/models/dbinbound';
import AdminsPage from '@/pages/admins/AdminsPage';
import InboundFormModal from '@/pages/inbounds/form/InboundFormModal';
import { buildRowActionsMenu } from '@/pages/inbounds/list/RowActions';
import { HttpUtil } from '@/utils';

import { renderWithProviders } from './test-utils';

const { messageError } = vi.hoisted(() => ({ messageError: vi.fn() }));

vi.mock('antd', async (importOriginal) => {
  const actual = await importOriginal<typeof import('antd')>();
  return {
    ...actual,
    message: {
      ...actual.message,
      useMessage: () => [{ error: messageError, success: vi.fn() }, null],
    },
  };
});

const adminHooks = vi.hoisted(() => ({
  useVpnAdminsQuery: vi.fn(),
  useVpnPermissionsQuery: vi.fn(),
  useVpnAdminInboundsQuery: vi.fn(),
  useVpnAdminMutations: vi.fn(),
}));

vi.mock('@/api/queries/useVpnAdmins', () => adminHooks);

function mockAdminPageData() {
  adminHooks.useVpnAdminsQuery.mockReturnValue({
    admins: [],
    loading: false,
    fetched: true,
    fetchError: null,
    refetch: vi.fn(),
  });
  adminHooks.useVpnPermissionsQuery.mockReturnValue([]);
  adminHooks.useVpnAdminInboundsQuery.mockReturnValue([]);
  adminHooks.useVpnAdminMutations.mockReturnValue({
    add: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    reassign: vi.fn(),
  });
}

function renderAddModal() {
  return renderWithProviders(
    <InboundFormModal
      open
      mode="add"
      dbInbound={null}
      dbInbounds={[]}
      availableNodes={[]}
      onClose={() => {}}
      onSaved={() => {}}
    />,
  );
}

function vpnEditInbound() {
  return new DBInbound({
    id: 77,
    port: 51820,
    listen: '',
    protocol: 'l2tp',
    remark: 'tunnel main',
    enable: true,
    settings: {
      ipsecEnable: true,
      ipsecPsk: 'shared-secret',
      mtu: 1400,
      userLimit: 25,
      ipRanges: ['10.0.5.2-10.0.5.254'],
    },
    streamSettings: {},
    sniffing: {},
    nodeId: null,
    shareAddrStrategy: 'listen',
    shareAddr: '',
  });
}

function primaryButton(): HTMLElement {
  const button = document.querySelector('.ant-modal-footer .ant-btn-primary');
  if (!button) throw new Error('Primary modal button not found');
  return button as HTMLElement;
}

function modalCount(): number {
  return document.querySelectorAll('.ant-modal:not(.ant-modal-hidden)').length;
}

function visibleTabLabels(): string[] {
  return Array.from(document.querySelectorAll('.ant-tabs-tab'))
    .filter((tab) => !tab.classList.contains('ant-tabs-tab-hidden'))
    .map((tab) => (tab.textContent ?? '').trim());
}

async function chooseVpnProtocol(label: string) {
  const select = document.querySelector('#protocol') as HTMLSelectElement;
  if (!select) throw new Error('protocol select not found');
  const option = Array.from(select.options).find((item) => item.text === label);
  if (!option) throw new Error(`Option '${label}' not found`);
  await act(async () => {
    fireEvent.change(select, { target: { value: option.value } });
  });
}

describe('InboundFormModal — vpn protocols', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it('lists the vpn protocols in the picker without a "VPN Protocols" sentinel item', async () => {
    renderAddModal();
    const select = document.querySelector('#protocol') as HTMLSelectElement;
    const labels = Array.from(select.options).map((option) => option.text);
    expect(labels).toContain('L2TP/IPsec');
    expect(labels).toContain('OpenVPN');
    expect(labels).toContain('SSH');
    expect(labels).not.toContain('VPN Protocols');
    // xray protocols stay first in the same flat list
    expect(labels.indexOf('vmess')).toBeLessThan(labels.indexOf('L2TP/IPsec'));
  });

  it('keeps the same standard dialog open when a vpn protocol is picked', async () => {
    renderAddModal();
    expect(screen.getAllByRole('dialog').length).toBeGreaterThan(0);
    await chooseVpnProtocol('L2TP/IPsec');
    // No second dialog opened, and the picker hand-off did not close the form.
    expect(modalCount()).toBe(1);
    expect(document.querySelector('#protocol')).not.toBeNull();
    // The vpn protocols' tabs: Basics + Protocol (+ Advanced), no Stream/Security/Sniffing.
    const tabs = visibleTabLabels();
    expect(tabs).toContain('Basics');
    expect(tabs).toContain('Protocol');
    expect(tabs).not.toContain('Stream');
    expect(tabs).not.toContain('Security');
    expect(tabs).not.toContain('Sniffing');
  });

  it('shows the native Basics fields for a vpn protocol', async () => {
    renderAddModal();
    await chooseVpnProtocol('L2TP/IPsec');
    const labels = Array.from(document.querySelectorAll('.ant-form-item-label label'))
      .map((el) => (el.textContent ?? '').trim())
      .filter(Boolean);
    for (const expected of [
      'Address',
      'Share address strategy',
      'Subscription sort order',
      'Exclude from subscriptions',
      'Port',
      'Total Flow',
      'Traffic Reset',
      'Duration',
    ]) {
      expect(
        labels.some((label) => label.toLowerCase().includes(expected.toLowerCase())),
        `missing basics field: ${expected}`,
      ).toBe(true);
    }
  });

  it('renders the vpn protocol fields with tooltips in the Protocol tab', async () => {
    renderAddModal();
    await chooseVpnProtocol('L2TP/IPsec');
    fireEvent.click(screen.getByRole('tab', { name: 'Protocol' }));
    const dns1 = screen.getByRole('textbox', { name: 'DNS 1' });
    const describedBy = dns1.getAttribute('aria-describedby') ?? '';
    expect(describedBy).not.toBe('');
    const hintText = document.getElementById(describedBy)?.textContent ?? '';
    expect(hintText).toContain('DNS server');
    // The switch fields carry real guidance too.
    const ipsecSwitch = screen.getByRole('switch', { name: 'IPsec on' });
    const ipsecHint = ipsecSwitch.getAttribute('aria-describedby') ?? '';
    expect(document.getElementById(ipsecHint)?.textContent).toContain('IPsec');
    // IP ranges editor is present with its own tooltip.
    expect(screen.getByRole('button', { name: 'Add' })).toBeTruthy();
  });

  it('saves a vpn inbound through the standard add endpoint without a separate dialog', async () => {
    const postSpy = vi
      .spyOn(HttpUtil, 'post')
      .mockResolvedValue({ success: true, msg: '', obj: null });
    renderAddModal();
    await chooseVpnProtocol('L2TP/IPsec');
    fireEvent.change(screen.getByLabelText('Remark'), { target: { value: 'office l2tp' } });
    await act(async () => {
      fireEvent.click(primaryButton());
    });
    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledTimes(1);
    });
    const [url, payload, options] = postSpy.mock.calls[0];
    expect(url).toBe('/panel/api/inbounds/add');
    expect((options as { headers?: Record<string, string> }).headers?.['Content-Type']).toBe(
      'application/json',
    );
    const body = payload as Record<string, unknown>;
    expect(body.protocol).toBe('l2tp');
    expect(body.remark).toBe('office l2tp');
    expect((body.settings as Record<string, unknown>).ipRanges).toEqual([]);
    // Basics state rides the same envelope: no total flow set → 0.
    expect(body.total).toBe(0);
    expect(modalCount()).toBe(1);
  });

  it('edits a vpn inbound in the standard dialog and preserves stored settings keys', async () => {
    const postSpy = vi
      .spyOn(HttpUtil, 'post')
      .mockResolvedValue({ success: true, msg: '', obj: null });
    const inbound = vpnEditInbound();
    renderWithProviders(
      <InboundFormModal
        open
        mode="edit"
        dbInbound={inbound}
        dbInbounds={[inbound]}
        availableNodes={[]}
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
    // Protocol picker shows the vpn protocol's display name.
    const select = document.querySelector('#protocol') as HTMLSelectElement;
    expect(select.options[Number(select.value)]?.text).toBe('L2TP/IPsec');
    fireEvent.click(screen.getByRole('tab', { name: 'Protocol' }));
    const ipsecSwitch = screen.getByRole('switch', { name: 'IPsec on' });
    expect(ipsecSwitch.getAttribute('aria-checked')).toBe('true');
    const rangeInput = screen.getByLabelText('IP Ranges 1') as HTMLInputElement;
    expect(rangeInput.value).toBe('10.0.5.2-10.0.5.254');
    await act(async () => {
      fireEvent.click(primaryButton());
    });
    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledTimes(1);
    });
    const [url, payload] = postSpy.mock.calls[0];
    expect(url).toBe('/panel/api/inbounds/update/77');
    const body = payload as Record<string, unknown>;
    const settings = body.settings as Record<string, unknown>;
    expect(settings.ipsecEnable).toBe(true);
    expect(settings.ipsecPsk).toBe('shared-secret');
    expect(settings.mtu).toBe(1400);
    expect(settings.userLimit).toBe(25);
    expect(settings.ipRanges).toEqual(['10.0.5.2-10.0.5.254']);
  });

  it('blocks a vpn save without a remark and without a valid port', async () => {
    const postSpy = vi
      .spyOn(HttpUtil, 'post')
      .mockResolvedValue({ success: true, msg: '', obj: null });
    renderAddModal();
    await chooseVpnProtocol('L2TP/IPsec');
    await act(async () => {
      fireEvent.click(primaryButton());
    });
    await waitFor(() => {
      expect(messageError).toHaveBeenCalled();
    });
    expect(postSpy).not.toHaveBeenCalled();
  });
});

describe('vpn row actions parity', () => {
  afterEach(() => {
    cleanup();
  });

  it('vpn rows get the exact native single-user dropdown: Inbound Information, Export Inbound, Reset Traffic, Clone, Delete', () => {
    const record = {
      id: 9,
      enable: true,
      remark: 'ssh relay',
      subSortIndex: 1,
      port: 22,
      protocol: 'ssh',
      up: 0,
      down: 0,
      total: 0,
      expiryTime: 0,
      _expiryTime: null,
      settings: {},
      streamSettings: {},
    };
    const items = buildRowActionsMenu({ record, subEnable: true, t: (key) => key }) ?? [];
    const keys = items.map((item) =>
      item && 'key' in item && item.key ? item.key : (item as { type?: string }).type,
    );
    expect(keys).toEqual(['showInfo', 'clipboard', 'resetTraffic', 'clone', 'divider', 'delete']);
    const labels = items.map((item) => (item && 'label' in item ? item.label : ''));
    expect(labels).toEqual([
      'pages.inbounds.inboundInfo',
      'pages.inbounds.exportInbound',
      'pages.inbounds.resetTraffic',
      'pages.inbounds.clone',
      '',
      'delete',
    ]);
  });
});

describe('page tooltips (Admins as the representative page)', () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('shows 3x-ui-style label tooltips on the add-admin form fields', async () => {
    mockAdminPageData();
    renderWithProviders(
      <MemoryRouter>
        <AdminsPage />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Add admin' }));
    await waitFor(() => {
      expect(document.querySelector('.admin-add-modal, .ant-modal-root')).not.toBeNull();
    });
    const tooltipIcons = document.querySelectorAll('.ant-form-item-tooltip');
    expect(tooltipIcons.length).toBeGreaterThanOrEqual(5);
  });
});
