import { fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { CoreCatalog, CoreStatusEnvelope } from '@/schemas/api/vpn';

import { renderWithProviders } from './test-utils';

const startProvision = vi.fn();

const statusEnvelope: CoreStatusEnvelope = {
  cores: [
    { name: 'xray', state: 'running', detail: '', version: '25.8.31', inbounds: 3 },
    {
      name: 'l2tp',
      state: 'not_installed',
      detail: 'xl2tpd not installed',
      version: '',
      inbounds: 0,
    },
    {
      name: 'ipsec',
      state: 'not_installed',
      detail: 'libreswan (ipsec) not installed',
      version: '',
      inbounds: 0,
    },
    { name: 'ssh', state: 'idle', detail: '', version: '1.0.2', inbounds: 0 },
    { name: 'openvpn', state: 'stopped', detail: '', version: '2.6.12', inbounds: 4 },
    { name: 'radius', state: 'not_installed', detail: '', version: '1.0.2', inbounds: 0 },
  ],
  system: {
    ipForward: true,
    nftables: true,
    iproute: true,
    modules: [{ name: 'tun', loaded: true, optional: false }],
    modulesOk: true,
  },
  provisioned: true,
  missingProtocols: [],
  rebootRequired: false,
  rebootModules: [],
  rebootPkg: '',
};

const catalog: CoreCatalog = {
  cores: [
    {
      name: 'l2tp',
      title: 'L2TP',
      backend: 'xl2tpd',
      desc: '',
      installed: false,
      inbounds: 0,
      shares: [],
      builtin: false,
    },
    {
      name: 'openvpn',
      title: 'OpenVPN',
      backend: 'OpenVPN',
      desc: '',
      installed: false,
      inbounds: 0,
      shares: [],
      builtin: false,
    },
    {
      name: 'ssh',
      title: 'SSH',
      backend: 'Built-in (pxpanel)',
      desc: '',
      installed: true,
      inbounds: 0,
      shares: [],
      builtin: true,
    },
    {
      name: 'xray',
      title: 'Xray',
      backend: 'Xray-core',
      desc: '',
      installed: true,
      inbounds: 0,
      shares: [],
      builtin: true,
    },
    {
      name: 'radius',
      title: 'RADIUS',
      backend: 'Built-in (pxpanel)',
      desc: '',
      installed: true,
      inbounds: 0,
      shares: [],
      builtin: true,
    },
  ],
  provisioned: true,
};

vi.mock('@/layouts/AppSidebar', () => ({ default: () => <aside /> }));

vi.mock('@/api/queries/useVpnCore', () => ({
  useVpnCoreStatus: () => ({ status: statusEnvelope, loading: false, refetch: vi.fn() }),
  useVpnCoreCatalog: () => catalog,
  useVpnProvisionStatus: () => ({ data: undefined }),
  useVpnUninstallStatus: () => ({ data: undefined }),
  useVpnCoreLogs: () => ({ data: undefined, isFetching: false, refetch: vi.fn() }),
  useVpnCoreConfig: () => ({ data: undefined, isFetching: false, refetch: vi.fn() }),
  useVpnCoreMutations: () => ({
    restart: vi.fn().mockResolvedValue({ success: true }),
    restartAll: vi.fn().mockResolvedValue({ success: true }),
    stop: vi.fn().mockResolvedValue({ success: true }),
    reboot: vi.fn().mockResolvedValue({ success: true }),
    startProvision: (...args: unknown[]) => startProvision(...args),
    startUninstall: vi.fn().mockResolvedValue({}),
  }),
}));

import CoreSettingsPage from '@/pages/core/CoreSettingsPage';

describe('CoreSettingsPage (3x-ui redesign) smoke', () => {
  beforeEach(() => {
    startProvision.mockReset().mockResolvedValue({ running: true, done: false, steps: [] });
  });

  it('renders summary stats, localized state tags and the toolbar', () => {
    renderWithProviders(<CoreSettingsPage />);

    // Summary card tiles
    expect(screen.getByText('Cores')).toBeTruthy();
    // "Running" matches both the stat tile and the running row's tag
    expect(screen.getAllByText('Running').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('Not installed').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('Inbounds').length).toBeGreaterThanOrEqual(2);

    // Localized tags, not raw state strings
    expect(screen.getByText('Running', { selector: '.ant-tag' })).toBeTruthy();
    expect(screen.getByText('Idle', { selector: '.ant-tag' })).toBeTruthy();
    expect(screen.getByText('Stopped', { selector: '.ant-tag' })).toBeTruthy();
    expect(screen.getAllByText('Not installed', { selector: '.ant-tag' })).toHaveLength(3);
    expect(screen.queryByText('not_installed')).toBeNull();

    // Toolbar actions kept
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Provision' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Uninstall' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Restart all' })).toBeTruthy();

    // Host system card still present
    expect(screen.getByText('Host system')).toBeTruthy();
  });

  it('shows Install only for not-installed catalog cores; derived rows get none', () => {
    renderWithProviders(<CoreSettingsPage />);

    const installButtons = screen.getAllByRole('button', { name: 'Install' });
    // l2tp only: openvpn is installed-but-stopped here; ipsec/radius are
    // derived rows with nothing of their own to install
    expect(installButtons).toHaveLength(1);

    // Stop is offered only on the running row
    expect(screen.getAllByRole('button', { name: 'Stop' })).toHaveLength(1);
    // Restart/Logs/Configs icon buttons on every installed row (xray, ssh, openvpn)
    expect(screen.getAllByRole('button', { name: 'Restart' })).toHaveLength(3);
  });

  it('per-core Install confirms and provisions exactly that core', async () => {
    renderWithProviders(<CoreSettingsPage />);

    fireEvent.click(screen.getAllByRole('button', { name: 'Install' })[0]);
    expect((await screen.findAllByText('Install the L2TP/IPsec core?')).length).toBeGreaterThan(0);

    // Confirm the dialog (the last "Install" button is the dialog's OK)
    fireEvent.click(screen.getAllByRole('button', { name: 'Install' }).at(-1)!);
    await waitFor(() => expect(startProvision).toHaveBeenCalledWith(['l2tp']));

    // The shared provision console opens over the run
    expect(await screen.findByText('Provisioning console')).toBeTruthy();
  });
});
