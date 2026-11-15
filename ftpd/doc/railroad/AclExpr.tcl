# AclExpr
set all_graphs {
  ftpd/AclExpr
  {or
    {line
      {or
        'src 'dst
      }
      '=
      {optx
        'not
      }
      CIDR
    }
    {line
      {or
        'arg 'path 'user 'host
      }
      '=
      {optx
        'not
      }
      {optx
        'regex
      }
      {optx
        'caseless
      }
      string
    }
    {line
      'time '=
      {optx
        'not
      }
      timespecName
    }
    {line
      'authenticated '=
      {or
        'real 'anon 'yes 'no
      }
    }
    {line
      'protected '=
      {or
        'yes 'no
      }
    }
  }
}
