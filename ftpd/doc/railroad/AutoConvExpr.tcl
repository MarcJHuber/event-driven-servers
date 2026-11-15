# AutoConvExpr
set all_graphs {
  ftpd/AutoConvExpr
  {line
    'auto-conversion
    {or
      'gzip 'deflate 'checksum
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
