# ReadmeNotifyExpr
set all_graphs {
  ftpd/ReadmeNotifyExpr
  {line
    'readme-notify
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
