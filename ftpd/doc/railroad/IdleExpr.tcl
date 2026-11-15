# IdleExpr
set all_graphs {
  ftpd/IdleExpr
  {line
    'idle 'timeout
    {or
      'min 'max 'default
    }
    {optx
      Acl
    }
    '= seconds
  }
}
