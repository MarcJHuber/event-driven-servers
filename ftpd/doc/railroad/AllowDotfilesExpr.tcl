# AllowDotfilesExpr
set all_graphs {
  ftpd/AllowDotfilesExpr
  {line
    'allow-dotfiles
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
