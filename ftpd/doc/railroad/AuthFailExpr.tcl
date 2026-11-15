# AuthFailExpr
set all_graphs {
  ftpd/AuthFailExpr
  {line
    'authentication-failures
    {or
      'bye 'max
    }
    {optx
      Acl
    }
    '= number
  }
}
