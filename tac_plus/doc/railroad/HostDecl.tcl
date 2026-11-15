# HostDecl
set all_graphs {
  tac_plus/HostDecl
  {
    line 'host
    {optx
      'realm realmName
    }
    '= hostName '{
    {line
      {
        loop HostAttr
      }
    }
    '}
  }
}
