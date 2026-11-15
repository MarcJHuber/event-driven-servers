# ResolveIDsExpr
set all_graphs {
  ftpd/ResolveIDsExpr
  {line
    'resolve-ids
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
