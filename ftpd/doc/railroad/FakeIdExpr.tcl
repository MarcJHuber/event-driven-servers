# FakeIdExpr
set all_graphs {
  ftpd/FakeIdExpr
  {line
    {or
      'fake-owner 'fake-group
    }
    {optx
      Acl
    }
    '= string
  }
}
