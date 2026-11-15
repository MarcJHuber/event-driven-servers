# CheckExpr
set all_graphs {
  ftpd/CheckExpr
  {line
    {or
      'check-uid 'check-gid 'check-perm
    }
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
