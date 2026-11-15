# CmdAuthExpr
set all_graphs {
  ftpd/CmdAuthExpr
  {line
    'acl
    {optx
      'not
    }
    aclName '=
    {optx
      'log
    }
    {or
      'permit 'deny
    }
  }
}
