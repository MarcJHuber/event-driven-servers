# TransModeExpr
set all_graphs {
  ftpd/TransModeExpr
  {line
    'transmission-mode 'z
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
