import { lazy } from 'react';
import type { ComponentType } from 'react';
import {
  ApiOutlined,
  CloudUploadOutlined,
  ClusterOutlined,
  DashboardOutlined,
  ExportOutlined,
  GlobalOutlined,
  HddOutlined,
  ImportOutlined,
  SettingOutlined,
  ShopOutlined,
  SwapOutlined,
  TagsOutlined,
  TeamOutlined,
  ToolOutlined,
  UserOutlined,
} from '@ant-design/icons';

const IndexPage = lazy(() => import('@/pages/index/IndexPage'));
const InboundsPage = lazy(() => import('@/pages/inbounds/InboundsPage'));
const ClientsPage = lazy(() => import('@/pages/clients/ClientsPage'));
const GroupsPage = lazy(() => import('@/pages/groups/GroupsPage'));
const NodesPage = lazy(() => import('@/pages/nodes/NodesPage'));
const HostsPage = lazy(() => import('@/pages/hosts/HostsPage'));
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'));
const XrayPage = lazy(() => import('@/pages/xray/XrayPage'));
const ApiDocsPage = lazy(() => import('@/pages/api-docs/ApiDocsPage'));
const VpnOutboundsPage = lazy(() => import('@/pages/vpn-outbounds/VpnOutboundsPage'));
const ResellersPage = lazy(() => import('@/pages/resellers/ResellersPage'));
const AdminsPage = lazy(() => import('@/pages/admins/AdminsPage'));
const CoreSettingsPage = lazy(() => import('@/pages/core/CoreSettingsPage'));

export interface PanelRoute {
  path: string;
  titleKey: string;
  icon: ComponentType;
  component: ComponentType;
}

// The router, the sidebar, the page titles and the command palette all read this list, so a
// page cannot go missing from one of them.
export const PANEL_ROUTES: PanelRoute[] = [
  { path: '/', titleKey: 'menu.dashboard', icon: DashboardOutlined, component: IndexPage },
  { path: '/inbounds', titleKey: 'menu.inbounds', icon: ImportOutlined, component: InboundsPage },
  { path: '/clients', titleKey: 'menu.clients', icon: TeamOutlined, component: ClientsPage },
  { path: '/groups', titleKey: 'menu.groups', icon: TagsOutlined, component: GroupsPage },
  { path: '/nodes', titleKey: 'menu.nodes', icon: ClusterOutlined, component: NodesPage },
  { path: '/hosts', titleKey: 'menu.hosts', icon: GlobalOutlined, component: HostsPage },
  {
    path: '/vpn-outbounds',
    titleKey: 'menu.vpnOutbounds',
    icon: CloudUploadOutlined,
    component: VpnOutboundsPage,
  },
  { path: '/resellers', titleKey: 'menu.resellers', icon: ShopOutlined, component: ResellersPage },
  { path: '/admins', titleKey: 'menu.admins', icon: UserOutlined, component: AdminsPage },
  { path: '/core', titleKey: 'menu.core', icon: HddOutlined, component: CoreSettingsPage },
  { path: '/outbound', titleKey: 'menu.outbounds', icon: ExportOutlined, component: XrayPage },
  { path: '/routing', titleKey: 'menu.routing', icon: SwapOutlined, component: XrayPage },
  { path: '/settings', titleKey: 'menu.settings', icon: SettingOutlined, component: SettingsPage },
  { path: '/xray', titleKey: 'menu.xray', icon: ToolOutlined, component: XrayPage },
  { path: '/api-docs', titleKey: 'menu.apiDocs', icon: ApiOutlined, component: ApiDocsPage },
];

export const PANEL_ROUTE_PATHS = PANEL_ROUTES.map((route) => route.path);

export const PANEL_TITLE_KEYS: Record<string, string> = Object.fromEntries(
  PANEL_ROUTES.map((route) => [route.path, route.titleKey]),
);
