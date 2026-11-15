# ChmodMaskExpr
set all_graphs {
  ftpd/ChmodMaskExpr
  {line
    'chmod-mask
    {or
      'file 'directory
    }
    {optx
      Acl
    }
    '= octal
  }
}
