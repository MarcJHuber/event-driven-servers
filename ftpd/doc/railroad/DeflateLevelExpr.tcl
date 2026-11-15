# DeflateLevelExpr
set all_graphs {
  ftpd/DeflateLevelExpr
  {line
    'deflate-level
    {or
      'min 'max 'default
    }
    {optx
      Acl
    }
    '= digit
  }
}
