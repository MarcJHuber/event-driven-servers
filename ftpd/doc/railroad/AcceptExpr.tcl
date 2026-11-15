# AcceptExpr
set all_graphs {
  ftpd/AcceptExpr
  {line
    'accept 'timeout
    {optx
      Acl
    }
    '= seconds
  }
}
