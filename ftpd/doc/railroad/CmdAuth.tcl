# CmdAuth
set all_graphs {
  ftpd/CmdAuth
  {line
    'cmd '=
    {optx
      'site
    }
    command '{
    {optx
      CmdAuthExpr
    }
    '}
  }
}
