export const keys = {
  server: {
    status: () => ['server', 'status'] as const,
    networkInterfaces: () => ['server', 'networkInterfaces'] as const,
    fail2banStatus: () => ['server', 'fail2banStatus'] as const,
  },
  nodes: {
    root: () => ['nodes'] as const,
    list: () => ['nodes', 'list'] as const,
  },
  hosts: {
    root: () => ['hosts'] as const,
    list: () => ['hosts', 'list'] as const,
    raw: () => ['hosts', 'raw'] as const,
    byInbound: (inboundId: number) => ['hosts', 'byInbound', inboundId] as const,
    tags: () => ['hosts', 'tags'] as const,
  },
  subBalancers: {
    root: () => ['sub-balancers'] as const,
    list: () => ['sub-balancers', 'list'] as const,
  },
  settings: {
    root: () => ['settings'] as const,
    all: () => ['settings', 'all'] as const,
    defaults: () => ['settings', 'defaults'] as const,
    factoryDefaults: () => ['settings', 'factoryDefaults'] as const,
  },
  inbounds: {
    root: () => ['inbounds'] as const,
    slim: () => ['inbounds', 'slim'] as const,
    options: () => ['inbounds', 'options'] as const,
    amneziawgKernelReadiness: () => ['inbounds', 'amneziawgKernelReadiness'] as const,
  },
  clients: {
    root: () => ['clients'] as const,
    list: (params: unknown) => ['clients', 'list', params] as const,
    all: () => ['clients', 'all'] as const,
    onlines: () => ['clients', 'onlines'] as const,
    onlinesByGuid: () => ['clients', 'onlinesByGuid'] as const,
    activeInbounds: () => ['clients', 'activeInbounds'] as const,
    lastOnline: () => ['clients', 'lastOnline'] as const,
    groups: () => ['clients', 'groups'] as const,
    usageHistory: (email: string) => ['clients', 'usageHistory', email] as const,
  },
  xray: {
    root: () => ['xray'] as const,
    config: () => ['xray', 'config'] as const,
    outboundsTraffic: () => ['xray', 'outboundsTraffic'] as const,
    geodata: {
      root: () => ['xray', 'geodata'] as const,
      files: () => ['xray', 'geodata', 'files'] as const,
      categories: (file: string, query: string) =>
        ['xray', 'geodata', 'categories', file, query] as const,
      entries: (file: string, code: string, query: string, offset: number, limit: number) =>
        ['xray', 'geodata', 'entries', file, code, query, offset, limit] as const,
    },
    vpnOutbounds: {
      root: () => ['xray', 'vpnOutbounds'] as const,
      list: () => ['xray', 'vpnOutbounds', 'list'] as const,
      kinds: () => ['xray', 'vpnOutbounds', 'kinds'] as const,
      sshList: () => ['xray', 'vpnOutbounds', 'ssh'] as const,
    },
  },
  vpn: {
    root: () => ['vpn'] as const,
    accounts: {
      root: () => ['vpn', 'accounts'] as const,
      list: (params: unknown) => ['vpn', 'accounts', 'list', params] as const,
      assignable: () => ['vpn', 'accounts', 'assignable'] as const,
      balance: () => ['vpn', 'accounts', 'balance'] as const,
      online: () => ['vpn', 'accounts', 'online'] as const,
    },
    protocols: {
      root: () => ['vpn', 'protocols'] as const,
      addressing: (inboundId: number) => ['vpn', 'protocols', 'addressing', inboundId] as const,
      pools: () => ['vpn', 'protocols', 'pools'] as const,
      deviceConfigs: (inboundId: number, kind: string, email: string) =>
        ['vpn', 'protocols', 'deviceConfigs', inboundId, kind, email] as const,
      ikev2RemoteId: (inboundId: number) =>
        ['vpn', 'protocols', 'ikev2RemoteId', inboundId] as const,
    },
    admins: {
      root: () => ['vpn', 'admins'] as const,
      list: () => ['vpn', 'admins', 'list'] as const,
      permissions: () => ['vpn', 'admins', 'permissions'] as const,
      inbounds: () => ['vpn', 'admins', 'inbounds'] as const,
    },
    resellers: {
      root: () => ['vpn', 'resellers'] as const,
      list: () => ['vpn', 'resellers', 'list'] as const,
      inbounds: () => ['vpn', 'resellers', 'inbounds'] as const,
    },
    core: {
      root: () => ['vpn', 'core'] as const,
      status: () => ['vpn', 'core', 'status'] as const,
      catalog: () => ['vpn', 'core', 'catalog'] as const,
      provision: () => ['vpn', 'core', 'provision'] as const,
      uninstall: () => ['vpn', 'core', 'uninstall'] as const,
      logs: (core: string) => ['vpn', 'core', 'logs', core] as const,
      config: (core: string) => ['vpn', 'core', 'config', core] as const,
    },
  },
} as const;
